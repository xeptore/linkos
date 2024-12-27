package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/server"
)

var Version = "dev"

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, err := log.New()
	if nil != err {
		fmt.Fprintf(os.Stderr, "Error: failed to create logger: %v\n", err)
		return
	}
	logger = logger.With().Str("version", Version).Logger()

	defer func() {
		if err := recover(); nil != err {
			logger.Error().Func(log.Panic(err)).Msg("Panic recovered")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Context canceled before receiving a close signal")
		case <-c:
			logger.Warn().Msg("Close signal received. Exiting...")
			signal.Stop(c)
			cancel()
		}
	}()

	logger.WithLevel(log.Levelless).Msg("Starting server")

	if err := run(ctx, logger); nil != err {
		if !errors.Is(err, ctx.Err()) {
			if errors.Is(err, os.ErrNotExist) {
				logger.Error().Msg("Failed to run server as config file does not exist")
			} else {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to run server")
			}
		}
	}

	cancel()
	logger.Trace().Msg("Waiting for signal listener goroutine to return")
	wg.Wait()
	logger.Trace().Msg("Signal listener goroutine returned. Exiting...")
}

func run(ctx context.Context, logger zerolog.Logger) error {
	cfg, err := config.LoadServer("config.ini")
	if nil != err {
		return fmt.Errorf("config: failed to load: %w", err)
	}
	logger = logger.Level(cfg.LogLevel)
	logger.Debug().Dict("config", cfg.LogDict()).Msg("Loaded configuration")

	srv, err := server.New(logger, cfg.IPNet, cfg.BindHost, cfg.BindDev, cfg.BufferSize)
	if nil != err {
		return fmt.Errorf("server: failed to create server: %v", err)
	}
	return srv.Run(ctx)
}
