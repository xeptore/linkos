package update

import (
	"context"
	"fmt"

	"github.com/google/go-github/v67/github"
)

func NewerVersionExists(ctx context.Context, currentVersion string) (bool, error) {
	client := github.NewClient(nil)

	rls, _, err := client.Repositories.ListReleases(ctx, "xeptore", "linkos", &github.ListOptions{Page: 1, PerPage: 1})
	if nil != err {
		return false, fmt.Errorf("failed to list project releases: %v", err)
	}
	if l := len(rls); l != 1 {
		return false, fmt.Errorf("expected exactly 1 release to be returned, got: %d", l)
	}

	latestTag := rls[0].GetTagName()
	switch {
	case currentVersion == latestTag:
		return false, nil
	case currentVersion < latestTag:
		return true, nil
	default:
		return false, fmt.Errorf("unexpected condition: current version %q is more recent than latest release version %q", currentVersion, latestTag)
	}
}
