package config

import (
	"github.com/rs/zerolog"
)

const (
	DefaultServerLogLevel                = zerolog.InfoLevel
	DefaultClientLogLevel                = zerolog.InfoLevel
	DefaultClientTunDeviceMTU            = 1280
	DefaultBufferSize                    = 1280
	DefaultServerInitialAllocatedClients = 15
	DefaultServerCleanupIntervalSec      = 5 * 60
	DefaultKeepAliveIntervalSec          = 15
	DefaultMissedKeepAliveThreshold      = 3
	DefaultMaxKernelSendBufferSize       = 2097152
	DefaultMaxKernelRecvBufferSize       = 4194304
)
