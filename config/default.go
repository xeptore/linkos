package config

import (
	"github.com/rs/zerolog"
)

const (
	DefaultServerLogLevel                      = zerolog.InfoLevel
	DefaultClientLogLevel                      = zerolog.InfoLevel
	DefaultServerBufferSize                    = 256
	DefaultClientBufferSize                    = 256
	DefaultServerBufferPoolInitialSeeds        = 100
	DefaultServerInitialClientsCap             = 15
	DefaultServerCleanupIntervalSec            = 5 * 60
	DefaultServerInactiveConnectionEvictionSec = 1 * 60
)
