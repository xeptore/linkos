//go:build windows && amd64

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	wapi "github.com/iamacarpet/go-win64api"
	"github.com/rs/zerolog"
	"github.com/samber/mo"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/kernel32"
	"github.com/xeptore/linkos/winnsapi"
)

const (
	TunGUID     = "{BF663C0F-5A47-4720-A8CB-BEFD5A7A4633}"
	TunRingSize = 0x400000
)

type (
	Packet  []byte
	Packets <-chan mo.Result[Packet]
)

type Tun struct {
	adapter   *wintun.Adapter
	session   wintun.Session
	stopEvent windows.Handle
	logger    zerolog.Logger
}

func New(logger zerolog.Logger) (*Tun, error) {
	logger.Debug().Str("version", wintun.Version()).Msg("Loading wintun")

	guid, err := windows.GUIDFromString(TunGUID)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to parse adapter GUID: %v", err)
	}

	logger.Trace().Str("guid", TunGUID).Msg("Creating adapter")
	adapter, err := wintun.CreateAdapter("Linkos", "Linkos", &guid)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to create adapter: %v", err)
	}
	logger.Debug().Msg("Adapter created")

	logger.Trace().Msg("Starting session")
	session, err := adapter.StartSession(TunRingSize)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to start session: %v", err)
	}
	logger.Debug().Msg("Session successfully created")

	stopEvent, err := kernel32.CreateEvent(true, false, "StopEvent")
	if nil != err {
		return nil, fmt.Errorf("tun: failed to create kernel StopEvent: %v", err)
	}

	return &Tun{
		adapter:   adapter,
		session:   session,
		stopEvent: stopEvent,
		logger:    logger,
	}, nil
}

var afinetFamily = winipcfg.AddressFamily(windows.AF_INET)

func (t *Tun) AssignIPv4(ipv4 string) error {
	ip, err := netip.ParseAddr(ipv4)
	if nil != err {
		return fmt.Errorf("tun: failed to parse adapter IP address: %v", err)
	}
	t.logger.Debug().Str("addr", ip.String()).Msg("Parsed adater IP address")

	luid := winipcfg.LUID(t.adapter.LUID())

	prefix := netip.PrefixFrom(ip, 24)
	if err := luid.SetIPAddressesForFamily(afinetFamily, []netip.Prefix{prefix}); nil != err {
		return fmt.Errorf("tun: failed to set adapter IP address: %v", err)
	}
	t.logger.Debug().Str("prefix", prefix.String()).Msg("Parsed adapter IP prefix")

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
	if err := luid.SetDNS(afinetFamily, dnsServerAddrs, nil); nil != err {
		return fmt.Errorf("tun: failed to set DNS servers for adapter: %v", err)
	}
	if err := luid.FlushDNS(afinetFamily); nil != err {
		return fmt.Errorf("tun: failed to flush DNS: %v", err)
	}
	if err := winnsapi.FlushResolverCache(); nil != err {
		return fmt.Errorf("tun: failed to flush DNS resolver cache: %v", err)
	}
	// disablednsregistration

	return nil
}

func (t *Tun) SetIPv4Options() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	iface, err := luid.IPInterface(afinetFamily)
	if err != nil {
		return err
	}
	iface.ForwardingEnabled = true
	iface.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	iface.DadTransmits = 0
	iface.ManagedAddressConfigurationSupported = false
	iface.OtherStatefulConfigurationSupported = false
	iface.NLMTU = config.DefaultClientTunDeviceMTU
	iface.UseAutomaticMetric = false
	iface.Metric = 0
	if err := iface.Set(); nil != err {
		return fmt.Errorf("tun: failed to save interface options: %v", err)
	}
	return nil
}

func (t *Tun) FixFirewallRules(localIP, remoteAddr string) error {
	absPath, err := filepath.Abs(os.Args[0])
	if nil != err {
		return fmt.Errorf("tun: failed to get process absolute path: %v", err)
	}
	t.logger.Debug().Str("path", absPath).Msg("Found process absolute path")

	remoteIP, remotePort, err := net.SplitHostPort(remoteAddr)
	if nil != err {
		return fmt.Errorf("tun: failed to split remote host port: %v", err)
	}
	t.logger.Debug().Str("ip", remoteIP).Str("port", remotePort).Msg("Split remote address")

	var (
		pingRuleName = "linkos (" + absPath + ") - ping"
		udpRuleName  = "linkos (" + absPath + ") - udp"
	)

	t.logger.Debug().Msg("Deleting possibly existing ping firewall rule")
	for {
		if ok, err := wapi.FirewallRuleDelete(pingRuleName); nil != err {
			return fmt.Errorf("tun: failed to delete existing ping firewall rule: %v", err)
		} else if !ok {
			break
		}
	}
	t.logger.Debug().Msg("Deleted possibly existing ping firewall rule")

	t.logger.Debug().Msg("Adding ping firewall rule")
	pingRule := wapi.FWRule{ //nolint:exhaustruct
		Name:              pingRuleName,
		ApplicationName:   absPath,
		Enabled:           true,
		Protocol:          wapi.NET_FW_IP_PROTOCOL_ICMPv4,
		Direction:         wapi.NET_FW_RULE_DIR_IN,
		Action:            wapi.NET_FW_ACTION_ALLOW,
		Description:       "Allow Linkos peers to ping this machine",
		LocalAddresses:    localIP + "/255.255.255.255",
		RemoteAddresses:   remoteIP + "/255.255.255.0",
		Profiles:          wapi.NET_FW_PROFILE2_PUBLIC,
		ICMPTypesAndCodes: "0:0",
	}
	if _, err := wapi.FirewallRuleAddAdvanced(pingRule); nil != err {
		return fmt.Errorf("tun: fail to add firewall ping rule: %v", err)
	}
	t.logger.Debug().Msg("Added ping firewall rule")

	t.logger.Debug().Msg("Deleting possibly existing udp firewall rule")
	for {
		if ok, err := wapi.FirewallRuleDelete(udpRuleName); nil != err {
			return fmt.Errorf("tun: failed to delete existing udp firewall rule: %v", err)
		} else if !ok {
			break
		}
	}
	t.logger.Debug().Msg("Deleted possibly existing udp firewall rule")

	t.logger.Debug().Msg("Adding possibly existing udp firewall rule")
	udpRule := wapi.FWRule{ //nolint:exhaustruct
		Name:            udpRuleName,
		ApplicationName: absPath,
		Enabled:         true,
		Protocol:        wapi.NET_FW_IP_PROTOCOL_UDP,
		Direction:       wapi.NET_FW_RULE_DIR_IN,
		Action:          wapi.NET_FW_ACTION_ALLOW,
		Description:     "Allow Linkos peers to communicate with this machine",
		RemotePorts:     remotePort,
		LocalAddresses:  localIP + "/255.255.255.255",
		RemoteAddresses: remoteIP + "/255.255.255.0",
		Profiles:        wapi.NET_FW_PROFILE2_PUBLIC,
	}
	if _, err := wapi.FirewallRuleAddAdvanced(udpRule); nil != err {
		return fmt.Errorf("tun: fail to add firewall UDP rule: %v", err)
	}
	t.logger.Debug().Msg("Added possibly existing udp firewall rule")

	return nil
}

func (t *Tun) Up(ctx context.Context) (Packets, error) {
	readEvent := t.session.ReadWaitEvent()

	out := make(chan mo.Result[Packet])
	go func() {
		for {
			select {
			case <-ctx.Done():
				out <- mo.Err[Packet](ctx.Err())
				return
			default:
				pckt, err := t.session.ReceivePacket()
				if nil != err {
					switch {
					case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
						res, err := kernel32.WaitForMultipleObjects([]windows.Handle{readEvent, t.stopEvent}, false, windows.INFINITE)
						switch res {
						case windows.WAIT_OBJECT_0:
							continue
						case windows.WAIT_OBJECT_0 + 1:
							return
						default:
							out <- mo.Err[Packet](fmt.Errorf("tun: unexpected result from wait to events: %v", err))
						}
					case errors.Is(err, windows.ERROR_HANDLE_EOF):
						out <- mo.Err[Packet](fmt.Errorf("tun: expected StopEvent to be set before closing the session: %v", err))
						return
					case errors.Is(err, windows.ERROR_INVALID_DATA):
						out <- mo.Err[Packet](errors.New("tun: send ring corrupt"))
						return
					default:
						out <- mo.Err[Packet](fmt.Errorf("tun: unexpected error received from session: %v", err))
						return
					}
				}

				pcktClone := make([]byte, len(pckt))
				copy(pcktClone, pckt)
				t.session.ReleaseReceivePacket(pckt)
				out <- mo.Ok(Packet(pcktClone))
			}
		}
	}()

	return out, nil
}

func (t *Tun) ReleasePacketBuffer(p Packet) {
	t.session.ReleaseReceivePacket(p)
}

func (t *Tun) Down() (err error) {
	if err := kernel32.SetEvent(t.stopEvent); nil != err {
		return fmt.Errorf("tun: failed to set StopEvent: %v", err)
	}
	defer func() {
		t.logger.Trace().Msg("Closing StopEvent handle")
		if stopErr := kernel32.CloseHandle(t.stopEvent); nil != stopErr {
			t.logger.Error().Err(stopErr).Msg("Failed to close StopEvent handle")
		} else {
			t.logger.Trace().Msg("Closed StopEvent handle")
		}
	}()

	stopWaitDur := time.Second * 5
	if exited := t.waitForExit(uint32(stopWaitDur.Milliseconds())); !exited { //nolint:gosec
		return fmt.Errorf("tun: timed out waiting for receive ring stop after %s", stopWaitDur.String())
	}

	t.logger.Trace().Msg("Ending session")
	t.session.End()
	t.logger.Debug().Msg("Successfully ended session")

	t.logger.Trace().Msg("Closing adapter")
	if err := t.adapter.Close(); nil != err {
		return fmt.Errorf("tun: failed to close adapter: %v", err)
	}
	t.logger.Debug().Msg("Successfully closed adapter")
	return nil
}

func (t *Tun) Write(p []byte) (n int, err error) {
	buffer, err := t.session.AllocateSendPacket(len(p))
	if nil != err {
		return 0, fmt.Errorf("failed to allocate space for send packet: %v", err)
	}
	copy(buffer, p)
	t.session.SendPacket(buffer)
	return len(buffer), nil
}

func (t *Tun) waitForExit(dur uint32) bool {
	res, _ := kernel32.WaitForSingleObject(t.stopEvent, dur)
	return res == windows.WAIT_OBJECT_0
}
