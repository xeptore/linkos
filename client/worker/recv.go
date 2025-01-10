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

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
)

type Recv struct {
	common
	bufferSize int
	session    io.Writer
}

func NewRecv(logger zerolog.Logger, cfg *config.Client, serverPort uint16, session io.Writer) *Recv {
	return &Recv{
		session:    session,
		bufferSize: cfg.BufferSize,
		common: common{
			serverHost:       cfg.ServerHost,
			serverPort:       serverPort,
			socketSendBuffer: 128, // For keep-alive packets
			socketRecvBuffer: cfg.SocketRecvBuffer,
			srcIP:            cfg.IP,
			logger:           logger,
		},
	}
}

func (w *Recv) Run(ctx context.Context) error {
	var connectFailedAttempts int
	for {
		conn, err := w.connect(ctx)
		if nil != err {
			if errors.Is(err, ctx.Err()) {
				w.logger.Debug().Msg("Finishing client loop as connecting to server was cancelled")
				return ctx.Err()
			}
			connectFailedAttempts++
			retryDelaySec := 2 * connectFailedAttempts
			w.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msgf("Failed to connect to server. Reconnecting in %d seconds", retryDelaySec)
			time.Sleep(time.Duration(retryDelaySec) * time.Second)
			continue
		} else {
			w.logger.Info().Msg("Connected to server")
		}

		return w.run(ctx, conn)
	}
}

func (w *Recv) run(ctx context.Context, conn *net.UDPConn) error {
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
				w.logger.Error().Func(errutil.TreeLog(err)).Err(err).Msg("Failed to close tunnel connection triggered by parent context closure")
			}
		} else {
			w.logger.Trace().Msg("Closed tunnel connection due to parent context closure")
		}
	}()

	wg.Add(1)
	go w.keepAlive(ctx, &wg, conn)

	return w.handleInbound(conn)
}

func (w *Recv) handleInbound(conn *net.UDPConn) error {
	var (
		logger = w.logger.With().Str("worker", "incoming").Logger()
		buffer = make([]byte, w.bufferSize)
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
