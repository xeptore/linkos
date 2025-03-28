//go:build windows && amd64

package worker

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/netutil"
	"github.com/xeptore/linkos/pool"
)

type Client struct {
	common
}

func NewClient(logger zerolog.Logger, cfg *config.Client, sessionWriter io.Writer, sessionReader <-chan *pool.Packet) *Client {
	return &Client{
		common: common{
			serverHost:       cfg.ServerHost,
			serverPort:       config.ClientBasePort + uint16(cfg.IP[3]) - 2,
			socketSendBuffer: cfg.SocketSendBuffer,
			socketRecvBuffer: cfg.SocketRecvBuffer,
			bufferSize:       cfg.BufferSize,
			sessionWriter:    sessionWriter,
			sessionReader:    sessionReader,
			srcIP:            cfg.IP,
			logger:           logger,
		},
	}
}

func (w *Client) Run(ctx context.Context) error {
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

func (w *Client) run(ctx context.Context, conn *net.UDPConn) (err error) {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error { // Close connection on context cancellation
		<-ctx.Done()
		w.logger.Trace().Msg("Closing tunnel connection due to parent context closure")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				w.logger.Error().Func(errutil.TreeLog(err)).Err(err).Msg("Failed to close tunnel connection triggered by parent context closure")
			}
		} else {
			w.logger.Trace().Msg("Closed tunnel connection due to parent context closure")
		}
		return nil
	})
	eg.Go(func() error { return w.keepAlive(ctx, conn) })
	eg.Go(func() error { return w.handleInbound(ctx, conn) })
	eg.Go(func() error { return w.handleOutbound(ctx, conn) })

	if err := eg.Wait(); nil != err {
		return err
	}
	return nil
}

func (w *Client) handleInbound(ctx context.Context, conn *net.UDPConn) error {
	var (
		logger = w.logger.With().Str("worker", "inbound").Logger()
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

		written, err := w.sessionWriter.Write(buffer[:n])
		switch {
		case nil != err:
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error writing to TUN device")
			if err := ctx.Err(); nil != err {
				// TUN device is expected to already been closed due to context cancellation.
				// Hence, this should be treated as a clean exit, which will be handled by the caller.
				return err
			}
			return err
		case written != n:
			logger.Error().Int("written", written).Int("expected", n).Msg("Failed to write all bytes to TUN device")
		default:
			logger.Trace().Int("bytes", n).Msg("Incoming packet has been written to TUN device")
		}
	}
}

func (w *Client) handleOutbound(ctx context.Context, conn *net.UDPConn) error {
	logger := w.logger.With().Str("worker", "outbound").Logger()
	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Finishing worker due to context cancellation")
			return ctx.Err()
		case packet := <-w.sessionReader:
			if packet == nil {
				return nil
			}
			if err := sendAndReleasePacket(logger, conn, packet); nil != err {
				return err
			}
		}
	}
}

func sendAndReleasePacket(logger zerolog.Logger, conn *net.UDPConn, p *pool.Packet) error {
	defer p.ReturnToPool()

	payload := p.B[:p.Size]
	if ok, err := filterOutgoingPacket(logger, payload); nil != err {
		logger.Debug().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to filter packet")
		return nil
	} else if !ok {
		logger.Trace().Msg("Dropping filtered packet")
		return nil
	}

	written, err := conn.Write(payload)
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
	case written != p.Size:
		logger.Error().Int("written", written).Int("expected", p.Size+1).Msg("Failed to write all bytes of packet to tunnel connection")
	default:
		logger.Trace().Int("bytes", written).Msg("Outgoing packet has been written to tunnel connection")
	}
	return nil
}
