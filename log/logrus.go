package log

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func New() (*logrus.Logger, error) {
	logger := logrus.New()
	//nolint:exhaustruct
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		DisableQuote:    true,
		FullTimestamp:   true,
		PadLevelText:    true,
		TimestampFormat: time.DateTime,
	})
	logger.SetLevel(logrus.DebugLevel)
	logger.SetOutput(os.Stderr)
	return logger, nil
}
