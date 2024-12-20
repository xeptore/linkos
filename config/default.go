package config

import (
	"github.com/rs/zerolog"
)

const (
	DefaultServerLogLevel                = zerolog.InfoLevel
	DefaultClientLogLevel                = zerolog.InfoLevel
	DefaultTunRingSize                   = 0x20000 // 2^17
	DefaultClientIncomingThreads         = 4
	DefaultClientTunDeviceMTU            = 1280
	DefaultBufferSize                    = 1280
	DefaultServerInitialAllocatedClients = 10
	DefaultServerCleanupIntervalSec      = 10 * 60
	DefaultKeepAliveIntervalSec          = 10
	DefaultMissedKeepAliveThreshold      = 5
	DefaultMaxKernelSendBufferSize       = 2 * 1024 * 1024 // 2 MiB
	DefaultMaxKernelRecvBufferSize       = 4 * 1024 * 1024 // 4 MiB
)
