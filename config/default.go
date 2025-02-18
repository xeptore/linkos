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
	DefaultServerLogLevel                      = zerolog.InfoLevel
	DefaultClientLogLevel                      = zerolog.InfoLevel
	DefaultTunRingSize                         = 7
	DefaultClientTunDeviceMTU                  = 1300
	DefaultBufferSize                          = 1300
	DefaultClientSocketRecvBuffer              = 4 * units.MiB
	DefaultClientSocketSendBuffer              = 4 * units.MiB
	DefaultServerMaxClients             uint16 = 9
	DefaultServerNumEventLoops                 = 0
	DefaultServerCleanupTickIntervalSec        = 5 * minute
	DefaultKeepAliveSec                        = 16 * second
	DefaultInactivityKeepAliveLimit            = 5
	DefaultServerSocketRecvBufferSize          = 4 * units.MiB
	DefaultServerSocketSendBufferSize          = 4 * units.MiB
	ClientBasePort                      uint16 = 15629
)

var DefaultHostPorts = []uint16{59989, 4937, 20573, 24525, 22163, 18151, 14526, 55599, 46539}
