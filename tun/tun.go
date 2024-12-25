//go:build windows && amd64

package tun

import (
	"fmt"
	"net/netip"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/kernel32"
	"github.com/xeptore/linkos/winnsapi"
	"github.com/xeptore/linkos/wintun"
)

const TunGUID = "{BF663C0F-5A47-4720-A8CB-BEFD5A7A4633}"

type Tun struct {
	adapter   *wintun.Adapter
	stopEvent windows.Handle
	ringSize  uint32
	logger    zerolog.Logger
}

type CreateError struct {
	Err error
}

func (err *CreateError) Error() string {
	return err.Err.Error()
}

func New(logger zerolog.Logger, ringSize uint32) (*Tun, error) {
	if ver, err := wintun.RunningVersion(); nil != err {
		logger.Error().Err(err).Msg("Failed to get wintun version")
	} else {
		logger.Debug().Str("version", ver).Msg("Loading wintun")
	}

	guid, err := windows.GUIDFromString(TunGUID)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to parse adapter GUID: %v", err)
	}

	if err := wintun.Uninstall(); nil != err {
		logger.Warn().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to uninstall wintun driver")
	}

	logger.Trace().Str("guid", TunGUID).Msg("Creating adapter")
	adapter, err := wintun.CreateAdapter("Linkos", "Linkos", &guid)
	if nil != err {
		return nil, &CreateError{fmt.Errorf("tun: failed to create adapter: %v", err)}
	}
	logger.Debug().Msg("Adapter created")

	stopEvent, err := kernel32.CreateEvent(true, false, "StopEvent")
	if nil != err {
		return nil, fmt.Errorf("tun: failed to create kernel StopEvent: %v", err)
	}

	return &Tun{
		adapter:   adapter,
		stopEvent: stopEvent,
		ringSize:  ringSize,
		logger:    logger,
	}, nil
}

var afInetFamily = winipcfg.AddressFamily(windows.AF_INET)

func (t *Tun) AssignIPv4(ip string) error {
	ipAddr, err := netip.ParseAddr(ip)
	if nil != err {
		return fmt.Errorf("tun: failed to parse adapter IP address: %v", err)
	}
	logger := t.logger.With().Str("ip", ipAddr.String()).Logger()
	logger.Debug().Msg("Parsed adater IP address")

	luid := winipcfg.LUID(t.adapter.LUID())

	prefix := netip.PrefixFrom(ipAddr, 24)
	if err := luid.SetIPAddressesForFamily(afInetFamily, []netip.Prefix{prefix}); nil != err {
		return fmt.Errorf("tun: failed to set adapter IP address: %v", err)
	}
	logger.Debug().Str("prefix", prefix.String()).Msg("Parsed adapter IP prefix")

	dnsServerAddrs := make([]netip.Addr, 0, 2)
	dnsServerAddr, err := netip.ParseAddr("1.1.1.2")
	if nil != err {
		return fmt.Errorf("tun: failed to parse DNS server address: %v", err)
	}
	dnsServerAddrs = append(dnsServerAddrs, dnsServerAddr)
	dnsServerAddr, err = netip.ParseAddr("9.9.9.11")
	if nil != err {
		return fmt.Errorf("tun: failed to parse DNS server address: %v", err)
	}
	dnsServerAddrs = append(dnsServerAddrs, dnsServerAddr)
	if err := luid.SetDNS(afInetFamily, dnsServerAddrs, nil); nil != err {
		return fmt.Errorf("tun: failed to set DNS servers for adapter: %v", err)
	}
	if err := luid.FlushDNS(afInetFamily); nil != err {
		return fmt.Errorf("tun: failed to flush DNS: %v", err)
	}
	if err := winnsapi.FlushResolverCache(); nil != err {
		return fmt.Errorf("tun: failed to flush DNS resolver cache: %v", err)
	}
	// disablednsregistration

	return nil
}

func (t *Tun) SetIPv4Options(mtu uint32) error {
	luid := winipcfg.LUID(t.adapter.LUID())
	iface, err := luid.IPInterface(afInetFamily)
	if nil != err {
		return err
	}
	iface.ForwardingEnabled = true
	iface.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	iface.DadTransmits = 0
	iface.ManagedAddressConfigurationSupported = false
	iface.OtherStatefulConfigurationSupported = false
	iface.NLMTU = mtu
	iface.Connected = true
	iface.DisableDefaultRoutes = true
	iface.Metric = 0
	iface.SitePrefixLength = 24
	iface.UseAutomaticMetric = false
	if err := iface.Set(); nil != err {
		return fmt.Errorf("tun: failed to save interface options: %v", err)
	}
	return nil
}

func (t *Tun) Down() (err error) {
	t.logger.Trace().Msg("Closing adapter")
	if err := t.adapter.Close(); nil != err {
		return fmt.Errorf("tun: failed to close adapter: %v", err)
	}
	t.logger.Debug().Msg("Successfully closed adapter")
	return nil
}
