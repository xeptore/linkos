package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/server"
)

var Version = "dev"

func main() {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger, err := log.New()
	if nil != err {
		fmt.Fprintf(os.Stderr, "Error: failed to create logger: %v\n", err)
		return
	}
	logger = logger.With().Str("version", Version).Logger()

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

	srv, err := server.New(logger, cfg.IPNet, cfg.BindAddr, cfg.BufferSize)
	if nil != err {
		return fmt.Errorf("server: failed to initialize: %v", err)
	}

	return srv.Run(ctx)
}
