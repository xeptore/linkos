package config

import (
	"github.com/rs/zerolog"
)

const (
	DefaultServerLogLevel                      = zerolog.InfoLevel
	DefaultClientLogLevel                      = zerolog.InfoLevel
	DefaultClientTunDeviceMTU                  = 1280
	DefaultServerBufferSize                    = 1280
	DefaultClientBufferSize                    = 1280
	DefaultServerBufferPoolInitialSeeds        = 100
	DefaultServerInitialClientsCap             = 15
	DefaultServerCleanupIntervalSec            = 5 * 60
	DefaultServerInactiveConnectionEvictionSec = 10 * 60
)
