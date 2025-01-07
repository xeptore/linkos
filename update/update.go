package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"

	"github.com/xeptore/linkos/dnsutil"
)

func NewerVersionExists(ctx context.Context, logger zerolog.Logger, currentVersion string) (exists bool, latestTag string, err error) {
	httpClient := http.DefaultClient
	httpClient.Transport = dnsutil.FromRoundTripper(http.DefaultTransport)
	client := github.NewClient(httpClient)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	latestRelease, err := getLatestRelease(ctx, client)
	if nil != err {
		return false, "", fmt.Errorf("update: failed to get latest release: %v", err)
	}

	latestTag = latestRelease.GetTagName()
	switch {
	case currentVersion == latestTag:
		return false, "", nil
	case currentVersion < latestTag:
		return true, latestTag, nil
	default:
		currRelease, _, err := client.Repositories.GetReleaseByTag(ctx, "xeptore", "linkos", currentVersion)
		if nil != err {
			return false, "", fmt.Errorf("update: failed to get current release info: %v", err)
		}
		if !currRelease.GetPrerelease() {
			return false, "", fmt.Errorf("update: unexpected condition: current version %q is more recent than latest release version %q", currentVersion, latestTag)
		}
		return false, latestTag, nil
	}
}

func AssetFilename() string {
	return "client_" + runtime.GOOS + "_" + runtime.GOARCH + ".zip"
}

func getLatestRelease(ctx context.Context, client *github.Client) (*github.RepositoryRelease, error) {
	var page int
	for {
		releases, err := getReleasePage(ctx, client, page)
		if nil != err {
			return nil, err
		}
		if len(releases) == 0 {
			return nil, errors.New("update: no releases found")
		}
		for _, rls := range releases {
			if !rls.GetPrerelease() {
				return rls, nil
			}
		}
		page++
	}
}

func getReleasePage(ctx context.Context, client *github.Client, page int) ([]*github.RepositoryRelease, error) {
	rls, _, err := client.Repositories.ListReleases(ctx, "xeptore", "linkos", &github.ListOptions{Page: page, PerPage: 100})
	if nil != err {
		return nil, fmt.Errorf("update: failed to list project releases: %v", err)
	}
	return rls, nil
}

func Download(ctx context.Context, tag string) (err error) {
	httpClient := http.DefaultClient
	httpClient.Transport = dnsutil.FromRoundTripper(http.DefaultTransport)
	client := github.NewClient(httpClient)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	release, _, err := client.Repositories.GetReleaseByTag(ctx, "xeptore", "linkos", tag)
	if nil != err {
		return fmt.Errorf("update: failed to get release info: %v", err)
	}

	var (
		assetID       int64
		assetFilename = AssetFilename()
	)
	for _, asset := range release.Assets {
		if asset.GetName() == assetFilename {
			assetID = asset.GetID()
			break
		}
	}

	asset, _, err := client.Repositories.GetReleaseAsset(ctx, "xeptore", "linkos", assetID)
	if nil != err {
		return fmt.Errorf("update: failed to get asset file size: %v", err)
	}

	rc, _, err := client.Repositories.DownloadReleaseAsset(ctx, "xeptore", "linkos", assetID, httpClient)
	if nil != err {
		return fmt.Errorf("update: failed to download release asset: %v", err)
	}
	defer func() {
		if closeErr := rc.Close(); nil != closeErr {
			err = errors.Join(err, fmt.Errorf("update: failed to close release download stream: %v", closeErr))
		}
	}()

	dst, err := os.OpenFile(filepath.Join(processAbsPath(), assetFilename), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if nil != err {
		return fmt.Errorf("update: failed to open file for writing: %v", err)
	}
	defer func() {
		if closeErr := dst.Close(); nil != closeErr {
			err = errors.Join(err, fmt.Errorf("update: failed to close download destination file: %v", closeErr))
		}
	}()

	bar := progressbar.DefaultBytes(int64(asset.GetSize()), "Downloading")
	if _, err := io.Copy(io.MultiWriter(bar, dst), rc); nil != err {
		return fmt.Errorf("update: failed to write file: %v", err)
	}
	if err := dst.Sync(); nil != err {
		return fmt.Errorf("update: failed to sync file: %v", err)
	}
	if err := bar.Finish(); nil != err {
		return fmt.Errorf("update: failed to finish progress bar: %v", err)
	}
	return nil
}

func processAbsPath() string {
	return filepath.Dir(os.Args[0])
}
