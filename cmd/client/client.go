//go:build windows && amd64

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/xeptore/linkos/client/worker"
	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/pool"
	"github.com/xeptore/linkos/tun"
)

type Client struct {
	t      *tun.Tun
	cfg    *config.Client
	logger zerolog.Logger
}

func (c *Client) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

	session, err := c.t.StartSession(pool.New(c.cfg.BufferSize))
	if nil != err {
		return fmt.Errorf("client: failed to start session: %v", err)
	}

	reader := session.Reader(ctx)

	wg.Add(1)
	go func() {
		defer wg.Done()

		<-ctx.Done()

		c.logger.Debug().Msg("Closing the session due to context cancellation")
		if err := session.Close(); nil != err {
			c.logger.Error().Func(errutil.TreeLog(err)).Err(err).Msg("Failed to close session")
		} else {
			c.logger.Debug().Msg("Session successfully closed")
		}

		if err := reader.Close(); nil != err {
			if !errors.Is(err, ctx.Err()) {
				c.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to close session packet reader")
			}
		} else {
			c.logger.Debug().Msg("Closed session packet reader")
		}
	}()

	for {
		eg, egCtx := errgroup.WithContext(ctx)
		for idx, port := range config.DefaultClientRecvPorts {
			w := worker.NewRecv(
				c.logger.With().Str("kind", "recv").Int("worker_id", idx).Logger(),
				c.cfg,
				port,
				session,
			)
			eg.Go(func() error { return w.Run(egCtx) })
		}

		for idx, port := range config.DefaultClientSendPorts {
			w := worker.NewSend(
				c.logger.With().Str("kind", "send").Int("worker_id", idx).Logger(),
				c.cfg,
				port,
				reader.Packets,
			)
			eg.Go(func() error { return w.Run(egCtx) })
		}

		_ = eg.Wait() // At least one worker should fail with error
		if err := ctx.Err(); nil != err {
			return ctx.Err()
		}
		c.logger.Warn().Msg("Detected worker disconnect. Recreating workers...")
	}
}
