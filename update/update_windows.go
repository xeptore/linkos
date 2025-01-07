package update

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sys/windows"

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
		return false, latestTag, nil
	case currentVersion < latestTag:
		return true, latestTag, nil
	default:
		if curRelease, _, err := client.Repositories.GetReleaseByTag(ctx, "xeptore", "linkos", currentVersion); nil != err {
			return false, "", fmt.Errorf("update: failed to get current release info: %v", err)
		} else if !curRelease.GetPrerelease() {
			return false, "", fmt.Errorf("update: unexpected condition: current version %q is more recent than latest release version %q", currentVersion, latestTag)
		} else {
			return false, latestTag, nil
		}
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

	dstFilePath := filepath.Join(processDir(), assetFilename)
	dst, err := os.OpenFile(dstFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if nil != err {
		return fmt.Errorf("update: failed to open file for writing: %v", err)
	}
	defer func() {
		if closeErr := dst.Close(); nil != closeErr {
			err = errors.Join(err, fmt.Errorf("update: failed to close download destination file: %v", closeErr))
		}
		if removeErr := os.Remove(dstFilePath); nil != removeErr {
			err = errors.Join(err, fmt.Errorf("update: failed to remove downloaded zip archive: %v", removeErr))
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

	if err := unzip(); nil != err {
		return fmt.Errorf("update: failed to unzip downloaded zip archive: %v", err)
	}

	return nil
}

func processDir() string {
	return filepath.Dir(os.Args[0])
}

func ProcessFilePath() string {
	return filepath.Join(processDir(), "linkos.exe")
}

func BackupProcessFilePath() string {
	return ProcessFilePath() + ".old"
}

func unzip() (err error) {
	dstDir := processDir()
	archive, err := zip.OpenReader(filepath.Join(processDir(), AssetFilename()))
	if nil != err {
		return fmt.Errorf("unzip: failed to extract zip archive: %v", err)
	}
	defer func() {
		if closeErr := archive.Close(); nil != closeErr {
			err = errors.Join(err, fmt.Errorf("unzip: failed to close downloaded zip archive: %v", err))
		}
	}()

	var (
		runningExeFileName = ProcessFilePath()
		backupExeFileName  = BackupProcessFilePath()
	)
	if err := os.Rename(runningExeFileName, backupExeFileName); nil != err {
		return err
	}

	if filenameW, err := windows.UTF16PtrFromString(backupExeFileName); nil != err {
		return fmt.Errorf("unzip: failed to convert running executable file name to Windows UTF16 string: %v", err)
	} else if err := windows.SetFileAttributes(filenameW, windows.FILE_ATTRIBUTE_HIDDEN); nil != err {
		return fmt.Errorf("unzip: failed to set old executable as hidden: %v", err)
	}

	for _, f := range archive.File {
		if f.Name == "config.ini" {
			continue
		}
		if err := extractZIPFile(f, dstDir); nil != err {
			return fmt.Errorf("unzip: failed to extract file %q: %v", f.Name, err)
		}
	}

	return nil
}

func extractZIPFile(f *zip.File, dstDir string) (err error) {
	dstFilePath := filepath.Join(dstDir, f.Name)                                          //nolint:gosec
	if !strings.HasPrefix(dstFilePath, filepath.Clean(dstDir)+string(os.PathSeparator)) { // Mitigates ZIP slip vulnerability that can be caused due to above path concatenation: https://github.com/securego/gosec/issues/324#issuecomment-935927967
		return fmt.Errorf("unzip: failed to extract archive file %q as it is an invalid path", dstFilePath)
	}

	if f.FileInfo().IsDir() {
		if err := os.MkdirAll(dstFilePath, os.ModePerm); nil != err {
			return fmt.Errorf("unzip: failed to create archive file %q destination directory: %v", dstFilePath, err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dstFilePath), os.ModePerm); nil != err {
		return fmt.Errorf("unzip: failed to create archive file %q destination directory: %v", dstFilePath, err)
	}

	dstFile, err := os.OpenFile(dstFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if nil != err {
		return fmt.Errorf("unzip: failed to open destination archive file %q: %v", dstFilePath, err)
	}
	defer func() {
		if closeErr := dstFile.Close(); nil != closeErr {
			err = errors.Join(err, fmt.Errorf("unzip: failed to close archive file %q destination file: %v", f.Name, closeErr))
		}
	}()

	fileInArchive, err := f.Open()
	if nil != err {
		return fmt.Errorf("unzip: failed to open archive file %q for extraction: %v", f.Name, err)
	}
	defer func() {
		if closeErr := fileInArchive.Close(); nil != closeErr {
			err = errors.Join(err, fmt.Errorf("unzip: failed to close extracting archive file %q: %v", f.Name, closeErr))
		}
	}()

	if written, err := io.CopyN(dstFile, fileInArchive, f.FileInfo().Size()); nil != err {
		return fmt.Errorf("unzip: failed to save extracted archive file %q: %v", f.Name, err)
	} else if expected := f.FileInfo().Size(); written != expected {
		return fmt.Errorf("unzip: unexpected uncompressed bytes written to destination file, expected %d, got: %d", expected, written)
	}

	if err := dstFile.Sync(); nil != err {
		return fmt.Errorf("unzip: failed to sync archive file %q destination file: %v", f.Name, err)
	}

	return nil
}
