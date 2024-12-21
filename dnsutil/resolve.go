package dnsutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/errutil"
)

var dnsServers []string = []string{"149.112.112.112:53", "9.9.9.11:53", "9.9.9.9:53", "208.67.222.222:53", "208.67.220.220:53", "1.0.0.1:53"}

func ResolveAddr(ctx context.Context, logger zerolog.Logger, hostname string) (net.IP, error) {
	if ip := net.ParseIP(hostname); nil != ip {
		logger.Debug().Str("hostname", hostname).Msg("Skip hostname resolution as hostname is already IP address")
		return ip, nil
	}

	logger = logger.With().Str("hostname", hostname).Logger()

	for _, dnsServer := range dnsServers {
		logger = logger.With().Str("dns_server", dnsServer).Logger()
		logger.Debug().Msg("Resolving hostname using DNS server")

		client := new(dns.Client)
		client.Net = "tcp"
		client.Timeout = 3 * time.Second

		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

		response, _, err := client.ExchangeContext(ctx, message, dnsServer)
		if nil != err {
			if errors.Is(err, ctx.Err()) {
				logger.Debug().Err(err).Msg("Breaking hostname IP address resolution due to context cancellation")
				return nil, ctx.Err()
			}
			logger.Debug().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to resolve IP address using DNS server")
			continue
		}

		if len(response.Answer) > 0 {
			for _, ans := range response.Answer {
				if aRecord, ok := ans.(*dns.A); ok {
					return net.ParseIP(aRecord.A.String()), nil
				}
			}
		}
	}

	return nil, fmt.Errorf("dnsutil: failed to resolve hostname %s", hostname)
}

type Transport struct {
	Transport http.RoundTripper
	Logger    zerolog.Logger
}

func (c *Transport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, err := ResolveAddr(ctx, c.Logger, addr)
	if nil != err {
		return nil, fmt.Errorf("dnsutil: failed to resolve query: %v", err)
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, 443)) // Port 443 for HTTPS
	if nil != err {
		return nil, fmt.Errorf("dnsutil: failed to dial TCP connection: %v", err)
	}
	return conn, nil
}
