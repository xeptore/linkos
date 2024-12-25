package config

import (
	"regexp"
)

// Hostname regex based on RFC 1123.
var validHostnameRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$`)

func isValidHostname(host string) bool {
	return validHostnameRegexp.MatchString(host)
}
