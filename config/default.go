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
	DefaultServerCleanupIntervalSec      = 1 * 60
	DefaultKeepAliveIntervalSec          = 5
	DefaultMissedKeepAliveThreshold      = 3
	DefaultMaxKernelSendBufferSize       = 2 * 1024 * 1024 // 2 MiB
	DefaultMaxKernelRecvBufferSize       = 4 * 1024 * 1024 // 4 MiB
)
