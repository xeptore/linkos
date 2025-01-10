package config

import (
	"github.com/alecthomas/units"
	"github.com/rs/zerolog"
)

const (
	second = 1
	minute = 60 * second
	hour   = 60 * minute
)

const (
	DefaultServerLogLevel               = zerolog.InfoLevel
	DefaultClientLogLevel               = zerolog.InfoLevel
	DefaultTunRingSize                  = 1
	DefaultClientTunDeviceMTU           = 1280
	DefaultBufferSize                   = 1280
	DefaultClientSocketRecvBuffer       = 512 * units.KiB
	DefaultClientSocketSendBuffer       = 256 * units.KiB
	DefaultServerMaxClients             = 10
	DefaultServerNumEventLoops          = 0
	DefaultServerCleanupTickIntervalSec = 5 * minute
	DefaultKeepAliveSec                 = 25 * second
	DefaultInactivityKeepAliveLimit     = 5
	DefaultServerSocketRecvBufferSize   = 2 * units.MiB
	DefaultServerSocketSendBufferSize   = 1 * units.MiB
)

var (
	DefaultClientSendPorts = []uint16{48931, 52342, 47124, 53210}
	DefaultClientRecvPorts = []uint16{47556, 52811, 49673, 52388}
)
