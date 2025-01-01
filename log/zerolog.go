package log

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

func New() zerolog.Logger {
	return newLogger(
		zerolog.ConsoleWriter{ //nolint:exhaustruct
			Out:        os.Stderr,
			TimeFormat: time.DateTime,
		},
	)
}

func newLogger(o io.Writer) zerolog.Logger {
	return zerolog.
		New(o).
		Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()
}

const Levelless = zerolog.InfoLevel
