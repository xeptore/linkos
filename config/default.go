package config

import (
	"github.com/rs/zerolog"
)

const (
	DefaultServerLogLevel           = zerolog.InfoLevel
	DefaultClientLogLevel           = zerolog.InfoLevel
	DefaultTunRingSize              = 1
	DefaultClientTunDeviceMTU       = 1280
	DefaultBufferSize               = 1280
	DefaultServerMaxClients         = 10
	DefaultServerCleanupIntervalSec = 5 * 60
	DefaultKeepAliveIntervalSec     = 25
	DefaultMissedKeepAliveThreshold = 3
	DefaultMaxKernelSendBufferSize  = 2 * 1024 * 1024 // 2 MiB
	DefaultMaxKernelRecvBufferSize  = 4 * 1024 * 1024 // 4 MiB
)

var (
	DefaultClientSendPorts = []uint16{48931, 52342, 47124, 53210}
	DefaultClientRecvPorts = []uint16{47556, 52811, 49673, 52388}
)
