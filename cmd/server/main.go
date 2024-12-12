package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/server"
)

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

	if err := run(ctx, logger); nil != err {
		logger.WithError(err).Error("Failed to run the application")
		return
	}
}

func run(ctx context.Context, logger *logrus.Logger) error {
	cfg, err := config.LoadServer("config.ini")
	if nil != err {
		return fmt.Errorf("config: failed to load: %v", err)
	}
	logger.SetLevel(cfg.LogLevel)

	srv, err := server.New(logger, cfg.SubnetCIDR, cfg.BindAddr, cfg.BufferSize)
	if nil != err {
		return fmt.Errorf("server: failed to initialize: %v", err)
	}

	return srv.Run(ctx)
}
