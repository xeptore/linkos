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
	DefaultTunRingSize                  = 5
	DefaultClientTunDeviceMTU           = 1280
	DefaultBufferSize                   = 1280
	DefaultClientSocketRecvBuffer       = 2 * units.MiB
	DefaultClientSocketSendBuffer       = 2 * units.MiB
	DefaultServerMaxClients             = 10
	DefaultServerNumEventLoops          = 16
	DefaultServerCleanupTickIntervalSec = 5 * minute
	DefaultKeepAliveSec                 = 11 * second
	DefaultInactivityKeepAliveLimit     = 5
	DefaultServerSocketRecvBufferSize   = 4 * units.MiB
	DefaultServerSocketSendBufferSize   = 4 * units.MiB
)

var (
	DefaultClientSendPorts = []uint16{48931, 52342, 47124, 53210}
	DefaultClientRecvPorts = []uint16{47556, 52811, 49673, 52388}
)
