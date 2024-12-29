package update

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/rs/zerolog"

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
		return false, "", fmt.Errorf("update: unexpected condition: current version %q is more recent than latest release version %q", currentVersion, latestTag)
	}
}

func getLatestRelease(ctx context.Context, client *github.Client) (*github.RepositoryRelease, error) {
	var page int
	for {
		releases, err := getReleasePage(ctx, client, page)
		if nil != err {
			return nil, err
		}
		if len(releases) == 0 {
			return nil, fmt.Errorf("update: no releases found")
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
