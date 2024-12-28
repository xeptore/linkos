//go:build windows && amd64

package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/errutil"
)

type Recv struct {
	common
	session io.Writer
}

func NewRecv(logger zerolog.Logger, bufferSize int, srcIP net.IP, serverHost string, serverPort uint16, session io.Writer) *Recv {
	return &Recv{
		session: session,
		common: common{
			serverHost:      serverHost,
			serverPort:      serverPort,
			connID:          0,
			writeBufferSize: 128, // For keep-alive packets
			readBufferSize:  bufferSize,
			srcIP:           srcIP,
			logger:          logger,
		},
	}
}

func (w *Recv) Run(ctx context.Context, wg *sync.WaitGroup) {
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
				continue
			}
		}
	}
}

func (w *Recv) run(ctx context.Context, conn *Connection) error {
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

	return w.handleInbound(conn)
}

func (w *Recv) handleInbound(conn *Connection) error {
	var (
		logger = w.logger.With().Str("worker", "incoming").Logger()
		buffer = make([]byte, w.readBufferSize)
	)
	for {
		n, err := conn.Read(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				logger.Trace().Msg("Ending server tunnel worker due to connection closure")
			} else {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error receiving data from server tunnel")
			}
			return err
		}
		n-- // Ignore the last byte which is the connection ID
		logger.Trace().Int("bytes", n).Msg("Received bytes from server tunnel")

		written, err := w.session.Write(buffer[:n])
		switch {
		case nil != err:
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error writing to TUN device")
			return err
		case written != n:
			logger.Error().Int("written", written).Int("expected", n).Msg("Failed to write all bytes to TUN device")
		default:
			logger.Trace().Int("bytes", n).Msg("Incoming packet has been written to TUN device")
		}
	}
}
