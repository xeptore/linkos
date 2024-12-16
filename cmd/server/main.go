package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/config"
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

	var wg sync.WaitGroup
	wg.Add(1)
	defer func() {
		logger.Trace().Msg("Waiting for signal listener goroutine to return")
		wg.Wait()
		logger.Trace().Msg("Signal listener goroutine returned")
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		defer wg.Done()
		<-c
		logger.Info().Msg("Close signal received. Exiting...")
		signal.Stop(c)
		cancel()
	}()

	logger.WithLevel(log.NoLevel).Msg("Starting server")

	if err := run(ctx, logger); nil != err {
		logger.Error().Err(err).Msg("Failed to run the application")
		return
	}
}

func run(ctx context.Context, logger zerolog.Logger) error {
	cfg, err := config.LoadServer("config.ini")
	if nil != err {
		return fmt.Errorf("config: failed to load: %v", err)
	}
	logger = logger.Level(cfg.LogLevel)
	logger.Debug().Dict("config", cfg.LogDict()).Msg("Loaded configuration")

	srv, err := server.New(logger, cfg.IPNet, cfg.BindAddr, cfg.BufferSize)
	if nil != err {
		return fmt.Errorf("server: failed to initialize: %v", err)
	}

	return srv.Run(ctx)
}
