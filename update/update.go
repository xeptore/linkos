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
	rls, _, err := client.Repositories.ListReleases(ctx, "xeptore", "linkos", &github.ListOptions{Page: 1, PerPage: 1})
	if nil != err {
		return false, "", fmt.Errorf("update: failed to list project releases: %v", err)
	}
	if l := len(rls); l != 1 {
		return false, "", fmt.Errorf("update: expected exactly 1 release to be returned, got: %d", l)
	}

	latestTag = rls[0].GetTagName()
	switch {
	case currentVersion == latestTag:
		return false, "", nil
	case currentVersion < latestTag:
		return true, latestTag, nil
	default:
		return false, "", fmt.Errorf("update: unexpected condition: current version %q is more recent than latest release version %q", currentVersion, latestTag)
	}
}
