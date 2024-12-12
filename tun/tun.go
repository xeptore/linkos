//go:build windows && amd64

package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/samber/mo"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"github.com/xeptore/linkos/iphlpapi"
	"github.com/xeptore/linkos/kernel32"
)

const (
	TunGUID     = "{C2D7ECB3-0523-42C8-98AF-6FC52B4CC356}"
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
	logger    *logrus.Logger
}

func New(logger *logrus.Logger) (*Tun, error) {
	logger.WithField("version", wintun.Version()).Debug("Loading wintun")

	guid, err := windows.GUIDFromString(TunGUID)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to parse adapter GUID: %v", err)
	}

	logger.WithField("guid", TunGUID).Trace("Creating adapter")
	adapter, err := wintun.CreateAdapter("Linkos", "Linkos", &guid)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to create adapter: %v", err)
	}
	logger.Debug("Adapter created")

	logger.Trace("Starting session")
	session, err := adapter.StartSession(TunRingSize)
	if nil != err {
		return nil, fmt.Errorf("tun: failed to start session: %v", err)
	}
	logger.Debug("Session successfully created")

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

func (t *Tun) AssignIPv4(ipv4 string) error {
	ip := net.ParseIP(ipv4)
	if nil == ip {
		return errors.New("tun: failed to parse adapter IP address")
	}
	if err := iphlpapi.SetAdapterIPv4(t.adapter.LUID(), ip.To4(), 24); nil != err {
		return fmt.Errorf("failed to set adapter IP address: %v", err)
	}
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
		t.logger.Trace("Closing StopEvent handle")
		if stopErr := kernel32.CloseHandle(t.stopEvent); nil != stopErr {
			t.logger.WithError(stopErr).Error("Failed to close StopEvent handle")
		} else {
			t.logger.Trace("Closed StopEvent handle")
		}
	}()

	stopWaitDur := time.Second * 5
	if exited := t.waitForExit(uint32(stopWaitDur.Milliseconds())); !exited { //nolint:gosec
		return fmt.Errorf("tun: timed out waiting for receive ring stop after %s", stopWaitDur.String())
	}

	t.logger.Trace("Ending session")
	t.session.End()
	t.logger.Debug("Successfully ended session")

	t.logger.Trace("Closing adapter")
	if err := t.adapter.Close(); nil != err {
		return fmt.Errorf("tun: failed to close adapter: %v", err)
	}
	t.logger.Debug("Successfully closed adapter")
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
