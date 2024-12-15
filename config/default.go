package config

import (
	"github.com/rs/zerolog"
)

const (
	DefaultServerLogLevel                      = zerolog.InfoLevel
	DefaultClientLogLevel                      = zerolog.InfoLevel
	DefaultClientTunDeviceMTU                  = 1536
	DefaultServerBufferSize                    = 1536
	DefaultClientBufferSize                    = 1536
	DefaultServerBufferPoolInitialSeeds        = 100
	DefaultServerInitialClientsCap             = 15
	DefaultServerCleanupIntervalSec            = 5 * 60
	DefaultServerInactiveConnectionEvictionSec = 10 * 60
)
