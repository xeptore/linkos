//go:build windows && amd64

package winnsapi

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	moddnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDNSFlushResolverCache = moddnsapi.NewProc("DnsFlushResolverCache")
)

func isErrSuccess(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == 0 {
			return true
		}
	}
	return false
}

func FlushResolverCache() error {
	_, _, err := procDNSFlushResolverCache.Call(0, 0, 0, 0)
	if !isErrSuccess(err) {
		return err
	}
	return nil
}
