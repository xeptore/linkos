//go:build windows && amd64

package main

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/client/worker"
	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/pool"
	"github.com/xeptore/linkos/tun"
)

type Client struct {
	t          *tun.Tun
	serverHost string
	ip         net.IP
	bufferSize int
	logger     zerolog.Logger
}

func (c *Client) run(ctx context.Context) error {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	session, err := c.t.StartSession(pool.New(c.bufferSize))
	if nil != err {
		return fmt.Errorf("client: failed to start session: %v", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		c.logger.Debug().Msg("Closing the session due to context cancellation")
		if err := session.Close(); nil != err {
			c.logger.Error().Err(err).Msg("Failed to close session")
		} else {
			c.logger.Debug().Msg("Session successfully closed")
		}
	}()

	for idx, port := range config.DefaultClientRecvPorts {
		w := worker.NewRecv(
			c.logger.With().Str("kind", "recv").Int("worker_id", idx).Logger(),
			c.bufferSize,
			c.ip,
			c.serverHost,
			port,
			session,
		)
		wg.Add(1)
		go w.Run(ctx, &wg)
	}

	for idx, port := range config.DefaultClientSendPorts {
		w := worker.NewSend(
			c.logger.With().Str("kind", "send").Int("worker_id", idx).Logger(),
			c.bufferSize,
			c.ip,
			c.serverHost,
			port,
			session,
		)
		wg.Add(1)
		go w.Run(ctx, &wg)
	}

	wg.Wait()
	return ctx.Err()
}
