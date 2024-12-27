//go:build windows && amd64

package worker

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/netutil"
	"github.com/xeptore/linkos/pool"
)

type Send struct {
	common
	sessionReader <-chan *pool.Packet
}

func NewSend(logger zerolog.Logger, bufferSize int, srcIP net.IP, serverHost string, serverPort uint16, sessionReader <-chan *pool.Packet) *Send {
	return &Send{
		sessionReader: sessionReader,
		common: common{
			serverHost:      serverHost,
			serverPort:      serverPort,
			writeBufferSize: bufferSize,
			readBufferSize:  0, // Nothing is expected to be received on this socket
			srcIP:           srcIP,
			logger:          logger,
		},
	}
}

func (w *Send) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	var connectFailedAttempts int
	for {
		select {
		case <-ctx.Done():
			w.logger.Debug().Msg("Finishing client loop as parent context was cancelled")
			return
		default:
			conn, err := w.connect(ctx)
			if nil != err {
				if errors.Is(err, ctx.Err()) {
					w.logger.Debug().Msg("Finishing client loop as connecting to server was cancelled")
					return
				}
				connectFailedAttempts++
				retryDelaySec := 2 * connectFailedAttempts
				w.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msgf("Failed to connect to server. Reconnecting in %d seconds", retryDelaySec)
				time.Sleep(time.Duration(retryDelaySec) * time.Second)
				continue
			} else {
				w.logger.Info().Msg("Connected to server")
				connectFailedAttempts = 0
			}

			if err := w.run(ctx, conn); nil != err {
				// Pipe is broken due to issues with conn or context cancellation
				if err := ctx.Err(); nil != err {
					return
				}
				w.logger.Info().Msg("Reconnecting...")
				continue
			}
		}
	}
}

func (w *Send) run(ctx context.Context, conn *net.UDPConn) error {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	wg.Add(1)
	go func() { // Close connection on context cancellation
		defer wg.Done()
		<-ctx.Done()
		w.logger.Trace().Msg("Closing tunnel connection due to parent context closure")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				w.logger.Error().Err(err).Msg("Failed to close tunnel connection triggered by parent context closure")
			}
		} else {
			w.logger.Trace().Msg("Closed tunnel connection due to parent context closure")
		}
	}()

	wg.Add(1)
	go w.keepAlive(ctx, &wg, conn)

	wg.Add(1)
	go w.handleInbound(&wg, conn)

	return w.handleOutbound(conn)
}

func (w *Send) handleOutbound(conn *net.UDPConn) error {
	for packet := range w.sessionReader {
		if err := sendAndReleasePacket(w.logger, conn, packet); nil != err {
			return err
		}
	}
	return nil
}

func sendAndReleasePacket(logger zerolog.Logger, conn *net.UDPConn, p *pool.Packet) error {
	defer p.ReturnToPool()

	payload := p.Buf.B
	if ok, err := filterOutgoingPacket(logger, payload); nil != err {
		logger.Debug().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to filter packet")
		return nil
	} else if !ok {
		logger.Trace().Msg("Dropping filtered packet")
		return nil
	}

	packetSize := p.Size
	written, err := conn.Write(payload[:packetSize])
	switch {
	case nil != err:
		switch {
		case errors.Is(err, net.ErrClosed):
		case netutil.IsConnInterruptedError(err):
			logger.Warn().Msg("Failed to write packet to tunnel as connection was interrupted.")
		default:
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error sending data to server")
		}
		return err
	case written != packetSize:
		logger.Error().Int("written", written).Int("expected", packetSize).Msg("Failed to write all bytes of packet to tunnel connection")
	default:
		logger.Trace().Int("bytes", written).Msg("Outgoing packet has been written to tunnel connection")
	}
	return nil
}

func (w *Send) handleInbound(wg *sync.WaitGroup, conn *net.UDPConn) {
	defer wg.Done()

	logger := w.logger.With().Str("worker", "incoming").Logger()
	for {
		n, err := conn.Read([]byte{})
		if nil != err {
			if !errors.Is(err, net.ErrClosed) {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to discard incoming packet")
			}
			return
		} else {
			logger.Trace().Int("bytes", n).Msg("Incoming packet has been discarded")
		}
		continue
	}
}
