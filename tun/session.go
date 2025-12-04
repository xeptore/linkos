//go:build windows && amd64

package tun

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/kernel32"
	"github.com/xeptore/linkos/mathutil"
	"github.com/xeptore/linkos/pool"
	"github.com/xeptore/linkos/wintun"
)

type Session struct {
	s         *wintun.Session
	stopEvent windows.Handle
	pool      pool.Pool
	logger    zerolog.Logger
}

func (t *Tun) StartSession(p pool.Pool) (*Session, error) {
	t.logger.Trace().Msg("Starting session")

	session, err := t.adapter.StartSession(mathutil.ToPowerOf2(t.ringSize + 16))
	if nil != err {
		return nil, fmt.Errorf("tun: failed to start session: %v", err)
	}
	t.logger.Debug().Msg("Session successfully created")

	return &Session{
		s:         session,
		stopEvent: t.stopEvent,
		pool:      p,
		logger:    t.logger.With().Logger(),
	}, nil
}

func (s *Session) Close() error {
	if err := kernel32.SetEvent(s.stopEvent); nil != err {
		return fmt.Errorf("tun: failed to set StopEvent: %w", err)
	}
	defer func() {
		s.logger.Trace().Msg("Closing StopEvent handle")
		if stopErr := kernel32.CloseHandle(s.stopEvent); nil != stopErr {
			s.logger.Error().Err(stopErr).Func(errutil.TreeLog(stopErr)).Msg("Failed to close StopEvent handle")
		} else {
			s.logger.Trace().Msg("Closed StopEvent handle")
		}
	}()

	stopWaitDur := time.Second * 5
	if exited := s.waitForExit(uint32(stopWaitDur.Milliseconds())); !exited {
		return fmt.Errorf("tun: timed out waiting for receive ring stop after %s", stopWaitDur.String())
	}

	s.s.End()
	return nil
}

func (s *Session) waitForExit(dur uint32) bool {
	res, _ := kernel32.WaitForSingleObject(s.stopEvent, dur)
	return res == windows.WAIT_OBJECT_0
}

func (s *Session) Write(p []byte) (int, error) {
	buffer, err := s.s.AllocateSendPacket(len(p))
	if nil != err {
		return 0, fmt.Errorf("failed to allocate space for send packet: %v", err)
	}
	copy(buffer, p)
	s.s.SendPacket(buffer)
	return len(buffer), nil
}

type SessionReader struct {
	err     error
	cancel  context.CancelFunc
	wg      *sync.WaitGroup
	logger  zerolog.Logger
	Packets <-chan *pool.Packet
}

func (r *SessionReader) Close() error {
	r.cancel()
	r.wg.Wait()
	return r.err
}

func (s *Session) Reader(ctx context.Context) *SessionReader {
	var (
		readEvent = s.s.ReadWaitEvent()
		packets   = make(chan *pool.Packet, 100)
		wg        sync.WaitGroup
	)
	ctx, cancel := context.WithCancel(ctx)

	out := &SessionReader{
		err:     nil,
		cancel:  cancel,
		wg:      &wg,
		logger:  zerolog.Logger{},
		Packets: packets,
	}

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
			close(packets)
		}()

		for {
			select {
			case <-ctx.Done():
				out.err = ctx.Err()
				return
			default:
				packet, err := s.s.ReceivePacket()
				if nil != err {
					switch {
					case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
						res, err := kernel32.WaitForMultipleObjects([]windows.Handle{readEvent, s.stopEvent}, false, windows.INFINITE)
						switch res {
						case windows.WAIT_OBJECT_0 + 0:
							continue
						case windows.WAIT_OBJECT_0 + 1:
							s.logger.Debug().Msg("Received StopEvent. Closing...")
							return
						default:
							out.err = fmt.Errorf("tun: unexpected result from wait to events: %v", err)
							return
						}
					case errors.Is(err, windows.ERROR_HANDLE_EOF):
						out.err = fmt.Errorf("tun: expected StopEvent to be triggerred before closing the session: %v", err)
						return
					case errors.Is(err, windows.ERROR_INVALID_DATA):
						out.err = errors.New("tun: send ring corrupt")
						return
					default:
						out.err = fmt.Errorf("tun: unexpected error received from session: %v", err)
						return
					}
				}

				packetLen := len(packet)
				if packetLen > s.pool.PacketMaxSize {
					s.logger.
						Error().
						Int("packet_size", packetLen).
						Int("buffer_max_size", s.pool.PacketMaxSize).
						Msg("Packet received from TUN exceeds max buffer size. Dropping packet")
					continue
				}

				clone := s.pool.AcquirePacket(packetLen)
				if written := copy(clone.B, packet); written != len(packet) {
					s.logger.
						Error().
						Err(err).
						Int("packet_bytes", packetLen).
						Int("written_bytes", written).
						Msg("Unexpected written bytes in clone packet write")
				}
				s.s.ReleaseReceivePacket(packet)
				clone.Size = packetLen
				packets <- clone
			}
		}
	}()

	return out
}
