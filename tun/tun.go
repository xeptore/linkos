//go:build windows && amd64

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/rs/zerolog"
	"github.com/samber/mo"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/kernel32"
	"github.com/xeptore/linkos/pool"
	"github.com/xeptore/linkos/winnsapi"
	"github.com/xeptore/linkos/wintun"
)

const TunGUID = "{BF663C0F-5A47-4720-A8CB-BEFD5A7A4633}"

type Packets <-chan mo.Result[*pool.Packet]

type Tun struct {
	adapter   *wintun.Adapter
	session   wintun.Session
	stopEvent windows.Handle
	logger    zerolog.Logger
	pool      *pool.PacketPool
}

type CreateError struct {
	Err error
}

func (err *CreateError) Error() string {
	return err.Err.Error()
}

func New(logger zerolog.Logger, ringSize uint32, pool *pool.PacketPool) (*Tun, error) {
	v, err := wintun.RunningVersion()
	if nil != err {
		logger.Error().Err(err).Msg("Failed to get wintun version")
	} else {
		logger.Debug().Uint32("version", v).Msg("Loading wintun")
	}

	guid, err := windows.GUIDFromString(TunGUID)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to parse adapter GUID: %v", err)
	}

	if err := wintun.Uninstall(); nil != err {
		logger.Warn().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to uninstall wintun driver")
	}

	logger.Trace().Str("guid", TunGUID).Msg("Creating adapter")
	adapter, err := wintun.CreateAdapter("Linkos", "Linkos", &guid)
	if nil != err {
		return nil, &CreateError{fmt.Errorf("tun: failed to create adapter: %v", err)}
	}
	logger.Debug().Msg("Adapter created")

	logger.Trace().Msg("Starting session")
	session, err := adapter.StartSession(ringSize)
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
		pool:      pool,
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

func (t *Tun) Up(ctx context.Context) (Packets, error) {
	readEvent := t.session.ReadWaitEvent()

	out := make(chan mo.Result[*pool.Packet])
	go func() {
		for {
			select {
			case <-ctx.Done():
				out <- mo.Err[*pool.Packet](ctx.Err())
				return
			default:
				packet, err := t.session.ReceivePacket()
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
							out <- mo.Err[*pool.Packet](fmt.Errorf("tun: unexpected result from wait to events: %v", err))
						}
					case errors.Is(err, windows.ERROR_HANDLE_EOF):
						out <- mo.Err[*pool.Packet](fmt.Errorf("tun: expected StopEvent to be set before closing the session: %v", err))
						return
					case errors.Is(err, windows.ERROR_INVALID_DATA):
						out <- mo.Err[*pool.Packet](errors.New("tun: send ring corrupt"))
						return
					default:
						out <- mo.Err[*pool.Packet](fmt.Errorf("tun: unexpected error received from session: %v", err))
						return
					}
				}

				packetLen := len(packet)
				if packetLen > t.pool.PacketMaxSize {
					t.logger.Error().
						Int("packet_size", packetLen).
						Int("buffer_size", t.pool.PacketMaxSize).
						Msg("Packet received from TUN exceeds buffer size. Dropping packet")
					continue
				}

				clone := t.pool.AcquirePacket()
				clone.Payload.Write(packet)
				t.session.ReleaseReceivePacket(packet)
				clone.Size = packetLen
				out <- mo.Ok(clone)
			}
		}
	}()

	return out, nil
}

func (t *Tun) ReleasePacketBuffer(p []byte) {
	t.session.ReleaseReceivePacket(p)
}

func (t *Tun) Down() (err error) {
	if err := kernel32.SetEvent(t.stopEvent); nil != err {
		return fmt.Errorf("tun: failed to set StopEvent: %v", err)
	}
	defer func() {
		t.logger.Trace().Msg("Closing StopEvent handle")
		if stopErr := kernel32.CloseHandle(t.stopEvent); nil != stopErr {
			t.logger.Error().Err(stopErr).Dict("err_tree", errutil.Tree(stopErr).LogDict()).Msg("Failed to close StopEvent handle")
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
