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
	DefaultTunRingSize                  = 2
	DefaultClientTunDeviceMTU           = 1280
	DefaultBufferSize                   = 1280
	DefaultClientSocketRecvBuffer       = 2 * units.MiB
	DefaultClientSocketSendBuffer       = 2 * units.MiB
	DefaultServerMaxClients             = 10
	DefaultServerNumEventLoops          = 0
	DefaultServerCleanupTickIntervalSec = 5 * minute
	DefaultKeepAliveSec                 = 16 * second
	DefaultInactivityKeepAliveLimit     = 5
	DefaultServerSocketRecvBufferSize   = 4 * units.MiB
	DefaultServerSocketSendBufferSize   = 4 * units.MiB
)

var (
	defaultPorts       = []uint16{59989, 4937, 20573, 24525, 22163, 18151, 14526, 55599, 46539, 2353, 15629}
	DefaultHostPorts   = defaultPorts[:9]
	DefaultClientPorts = defaultPorts[9:11]
)
