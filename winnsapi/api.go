//go:build windows && amd64

package winnsapi

import (
	"golang.org/x/sys/windows"

	"github.com/xeptore/linkos/win"
)

var (
	moddnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDNSFlushResolverCache = moddnsapi.NewProc("DnsFlushResolverCache")
)

func FlushResolverCache() error {
	_, _, err := procDNSFlushResolverCache.Call(0, 0, 0, 0)
	if !win.IsErrSuccess(err) {
		return err
	}
	return nil
}
