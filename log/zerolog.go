package log

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

func New() (zerolog.Logger, error) {
	logger := zerolog.
		New(
			zerolog.ConsoleWriter{ //nolint:exhaustruct
				Out:        os.Stderr,
				TimeFormat: time.DateTime,
			},
		).
		Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()
	return logger, nil
}

const Levelless = zerolog.InfoLevel
