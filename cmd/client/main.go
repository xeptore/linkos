//go:build windows && amd64

package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/tun"
	"github.com/xeptore/linkos/update"
)

func init() {
	// Disable default standard logger to discard internal wintun log messages
	stdlog.SetOutput(io.Discard)
	stdlog.SetFlags(0)
}

var (
	Version        = "dev"
	configFileName = "config.ini"
	errSigTrapped  = context.DeadlineExceeded
)

func waitForEnter(ctx context.Context) {
	if cause := context.Cause(ctx); errors.Is(cause, errSigTrapped) {
		return
	}

	fmt.Fprint(os.Stdout, "Press enter to exit...")
	bufio.NewReader(io.LimitReader(os.Stdin, 1)).ReadBytes('\n') //nolint:errcheck
}

func main() {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	var wg sync.WaitGroup
	defer func() {
		cancel(nil)
		wg.Wait()
		waitForEnter(ctx)
	}()

	logger := zerolog.New(log.NewConsoleWriter(zerolog.ErrorLevel))
	cfg, err := config.LoadClient(configFileName)
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(configFileName, config.ClientConfigTemplate, 0o0600); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Config file was not found. Tried creating a template file but did not succeeded")
			} else {
				logger.Error().Msg("Config file was not found. A template is created with name %s. You should fill with proper values")
			}
		} else {
			logger.Error().Err(err).Msg("Failed to load config")
		}
		return
	}

	cliWriter := log.NewConsoleWriter(cfg.LogLevel)
	logger = zerolog.
		New(cliWriter).
		Level(zerolog.TraceLevel).
		With().
		Timestamp().
		Str("version", Version).
		Logger()

	if cfg.FileLogLevel != zerolog.Disabled {
		fileLogName := "log." + time.Now().UTC().Format("20060102150405") + ".jsonl"
		logger.Info().Str("file_name", fileLogName).Msg("Enabling file log writer")
		fileWriter, err := log.NewFileWriter(fileLogName)
		if nil != err {
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to create file log writer")
		} else {
			defer func() {
				logger = logger.Output(cliWriter)
				if err := fileWriter.Close(); nil != err {
					logger.Error().Err(err).Msg("Failed to close file log writer")
				} else {
					logger.Debug().Msg("Closed file log writer")
				}
			}()
			logger = logger.Output(
				zerolog.MultiLevelWriter(
					cliWriter,
					fileWriter,
				),
			)
		}
	}

	logger.Debug().Dict("config_options", cfg.LogDict()).Msg("Loaded configuration")
	logger.Info().Msg("Starting VPN client")

	defer func() {
		if err := recover(); nil != err {
			logger.Error().Func(log.Panic(err)).Msg("Panic recovered")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Context canceled before receiving a close signal")
		case <-c:
			logger.Warn().Msg("Close signal received. Exiting...")
			signal.Stop(c)
			cancel(errSigTrapped)
		}
	}()

	if err := os.RemoveAll(update.BackupProcessFilePath()); nil != err {
		logger.Error().Func(errutil.TreeLog(err)).Msg("Failed to remove old backup executable file")
	}

	if err := run(ctx, logger, cfg); nil != err {
		if cause := context.Cause(ctx); errors.Is(cause, errSigTrapped) {
			logger.Debug().Msg("Client returned due to receiving a signal")
		} else if createErr := new(tun.CreateError); errors.As(err, &createErr) {
			if errors.Is(createErr.Err, windows.ERROR_ACCESS_DENIED) {
				logger.Error().Msg("Failed to create VPN tunnel. Rerun the application as Administrator.")
			} else {
				logger.Error().Func(errutil.TreeLog(createErr.Err)).Err(createErr.Err).Msg("Failed to create VPN tunnel. Try restarting your machine if the problem persists.")
			}
		} else if openURLErr := new(OpenLatestVersionDownloadURLError); errors.As(err, &openURLErr) {
			logger.
				Error().
				Err(err).
				Func(errutil.TreeLog(err)).
				Func(func(e *zerolog.Event) {
					if logger.GetLevel() < zerolog.InfoLevel {
						e.Str("combined_output", string(openURLErr.CommandOut))
					}
				}).
				Str("download_url", openURLErr.URL).
				Msg("Failed to open download URL. You can still download it manually using the URL.")
		} else {
			logger.Error().Err(err).Msg("Failed to run the application")
		}
	}
}

type OpenLatestVersionDownloadURLError struct {
	URL        string
	CommandOut []byte
}

func (err *OpenLatestVersionDownloadURLError) Error() string {
	return "failed to open latest version download URL"
}

func run(ctx context.Context, logger zerolog.Logger, cfg *config.Client) (err error) {
	if Version != "dev" {
		logger.Trace().Str("current_version", Version).Msg("Checking for new releases")
		exists, latestTag, err := update.NewerVersionExists(ctx, logger, Version)
		switch {
		case nil != err:
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to check for newer version existence. Make sure you have internet access and rerun the application.")
			// return nil
		case exists:
			logger.Warn().Msg("Newer version exists, and is going to be downloaded...")
			if err := update.Download(ctx, latestTag); nil != err {
				if err := ctx.Err(); nil != err {
					return err
				}
				logger.Error().Func(errutil.TreeLog(err)).Msg("Failed to download latest release. Download link will be opened in a second.")
				downloadURL := "https://github.com/xeptore/linkos/releases/download/" + latestTag + "/" + update.AssetFilename()
				cmd := []string{"start", downloadURL}
				if out, err := exec.Command("cmd.exe", "/c", strings.Join(cmd, " ")).CombinedOutput(); nil != err { //nolint:gosec
					return &OpenLatestVersionDownloadURLError{URL: downloadURL, CommandOut: out}
				}
			} else {
				logger.Info().Msg("Newer version downloaded. Rerun the program.")
			}
			return nil
		case !exists && latestTag != Version:
			logger.Warn().Str("current_version", Version).Str("latest_version", latestTag).Msg("You are running a pre-release version.")
		default:
			logger.Info().Msg("Already running the latest version")
		}
	}

	logger.Trace().Msg("Initializing VPN tunnel")
	t, err := tun.New(logger.With().Str("module", "tun").Logger(), cfg.RingSize)
	if nil != err {
		return fmt.Errorf("tun: failed to create: %w", err)
	}
	logger.Info().Msg("VPN tunnel initialized")
	defer func() {
		logger.Trace().Msg("Shutting down VPN tunnel")
		if downErr := t.Down(); nil != downErr {
			err = fmt.Errorf("tun: failed to properly shutdown: %v", downErr)
		}
		logger.Trace().Msg("VPN tunnel successfully shutdown")
	}()

	logger.Trace().Msg("Assigning IP address to tunnel adapter")
	if err := t.AssignIPv4(cfg.IP); nil != err {
		return fmt.Errorf("tun: failed to assign IP address: %v", err)
	}
	logger.Info().Msg("Assigned IP address to tunnel adapter")

	logger.Debug().Msg("Setting adapter IPv4 options")
	if err := t.SetIPv4Options(cfg.MTU); nil != err {
		return fmt.Errorf("tun: failed to set adapter IPv4 options: %v", err)
	}
	logger.Debug().Msg("Set adapter IPv4 options")

	client := Client{
		t:      t,
		cfg:    cfg,
		logger: logger.With().Str("module", "client").Logger(),
	}

	logger.WithLevel(log.Levelless).Msg("Starting VPN client")
	return client.run(ctx)
}
