package tun

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/samber/mo"
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
}

func New() (*Tun, error) {
	log.Printf("Using wintun version %s.\n", wintun.Version())

	guid, err := windows.GUIDFromString(TunGUID)
	if nil != err {
		return nil, fmt.Errorf("failed to parse adapter GUID: %v", err)
	}

	log.Println("Creating adapter...")
	adapter, err := wintun.CreateAdapter("linkos", "linkos", &guid)
	if nil != err {
		return nil, fmt.Errorf("failed to create linkos adapter: %v", err)
	}

	log.Println("Starting session...")
	session, err := adapter.StartSession(TunRingSize)
	if nil != err {
		return nil, fmt.Errorf("failed to start session: %v", err)
	}
	log.Println("Session successfully created.")

	stopEvent, err := kernel32.CreateEvent(true, false, "StopEvent")
	if nil != err {
		return nil, fmt.Errorf("failed to create kernel StopEvent: %v", err)
	}

	return &Tun{
		adapter:   adapter,
		session:   session,
		stopEvent: stopEvent,
	}, nil
}

func (t *Tun) AssignIPv4(ipv4 string) error {
	ip := net.ParseIP(ipv4)
	if nil == ip {
		return errors.New("failed to parse adapter IP address")
	}
	if err := iphlpapi.SetAdapterIPv4(t.adapter.LUID(), ip.To4(), 24); nil != err {
		return fmt.Errorf("failed to set adapter IP address: %v", err)
	}
	log.Println("Successfully assigned adapter IP address.")
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
					switch err {
					case windows.ERROR_NO_MORE_ITEMS:
						res, err := kernel32.WaitForMultipleObjects([]windows.Handle{readEvent, t.stopEvent}, false, windows.INFINITE)
						switch res {
						case windows.WAIT_OBJECT_0:
							continue
						case windows.WAIT_OBJECT_0 + 1:
							return
						default:
							out <- mo.Err[Packet](fmt.Errorf("unexpected result from wait to events: %v", err))
						}
					case windows.ERROR_HANDLE_EOF:
						out <- mo.Err[Packet](fmt.Errorf("expected StopEvent to be set before closing the session: %v", err))
						return
					case windows.ERROR_INVALID_DATA:
						out <- mo.Err[Packet](errors.New("send ring corrupt"))
						return
					default:
						out <- mo.Err[Packet](fmt.Errorf("unexpected error received from session: %v", err))
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

func (t *Tun) Down() error {
	kernel32.SetEvent(t.stopEvent)
	defer kernel32.CloseHandle(t.stopEvent)

	stopWaitDur := time.Second * 5
	if exited := t.waitForExit(uint32(stopWaitDur.Milliseconds())); !exited {
		return fmt.Errorf("timed out waiting for receive ring stop after %s", stopWaitDur.String())
	}

	log.Println("Ending session...")
	t.session.End()
	log.Println("Successfully ended session")

	log.Println("Closing adapter")
	if err := t.adapter.Close(); nil != err {
		return err
	}
	log.Println("Successfully closed adapter.")
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
	switch res {
	case windows.WAIT_OBJECT_0:
		return true
	}
	return false
}
