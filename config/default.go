package config

import (
	"github.com/rs/zerolog"
)

const (
	second = 1
	minute = 60 * second
	hour   = 60 * minute
)

const (
	b   = 1
	kib = 1024 * b
	mib = 1024 * kib
	gib = 1024 * mib
)

const (
	DefaultServerLogLevel               = zerolog.InfoLevel
	DefaultClientLogLevel               = zerolog.InfoLevel
	DefaultTunRingSize                  = 1
	DefaultClientTunDeviceMTU           = 1280
	DefaultBufferSize                   = 1280
	DefaultClientSendBuffer             = 10 * kib
	DefaultClientSocketRecvBuffer       = 10 * kib
	DefaultServerMaxClients             = 10
	DefaultServerNumEventLoops          = 512
	DefaultServerCleanupTickIntervalSec = 5 * minute
	DefaultKeepAliveSec                 = 25 * second
	DefaultInactivityKeepAliveLimit     = 3
	DefaultServerSocketSendBufferSize   = 16 * kib
	DefaultServerSocketRecvBufferSize   = 16 * kib
)

var (
	DefaultClientSendPorts = []uint16{48931, 52342, 47124, 53210}
	DefaultClientRecvPorts = []uint16{47556, 52811, 49673, 52388}
)
