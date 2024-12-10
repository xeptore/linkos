package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

func New() (*logrus.Logger, error) {
	logger := logrus.New()
	logger.SetFormatter(new(logrus.TextFormatter))
	logger.SetLevel(logrus.DebugLevel)
	logger.SetOutput(os.Stderr)
	return logger, nil
}
