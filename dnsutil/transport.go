package dnsutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

func FromRoundTripper(rt http.RoundTripper) http.RoundTripper {
	dialer := &net.Dialer{ //nolint:exhaustruct
		Resolver: &net.Resolver{ //nolint:exhaustruct
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (conn net.Conn, err error) {
				for _, dnsServer := range dnsServers {
					d := net.Dialer{Timeout: 3 * time.Second} //nolint:exhaustruct
					conn, err = d.DialContext(ctx, "udp", dnsServer)
					if nil != err {
						continue
					}
					return conn, nil
				}
				return nil, fmt.Errorf("dnsutil: failed to resolve query %q: %v", address, err)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	rt.(*http.Transport).DialContext = dialContext
	return rt
}
