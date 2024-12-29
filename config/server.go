package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/units"
	"github.com/rs/zerolog"
	"gopkg.in/ini.v1"
)

func validateBufferSize(n int) error {
	if n < 0 || n > 65535 {
		return errors.New("out of range")
	}
	return nil
}

type Server struct {
	BindHost         string
	BindDev          string
	IPNet            string
	NumEventLoops    int
	SocketRecvBuffer int64
	SocketSendBuffer int64
	BufferSize       int
	LogLevel         zerolog.Level
}

func (s *Server) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("bind_host", s.BindHost).
		Str("bind_dev", s.BindDev).
		Str("ip_net", s.IPNet).
		Int("num_event_loops", s.NumEventLoops).
		Int64("socket_recv_buffer", s.SocketRecvBuffer).
		Int64("socket_send_buffer", s.SocketSendBuffer).
		Int("buffer_size", s.BufferSize).
		Str("log_level", s.LogLevel.String())
}

var allLogLevels = []zerolog.Level{
	zerolog.TraceLevel,
	zerolog.DebugLevel,
	zerolog.InfoLevel,
	zerolog.WarnLevel,
	zerolog.ErrorLevel,
	zerolog.FatalLevel,
	zerolog.PanicLevel,
}

func LoadServer(filename string) (*Server, error) {
	cfg, err := ini.Load(filename)
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("config: failed to load: %v", err)
	}

	bindHost := strings.TrimSpace(cfg.Section("").Key("bind_host").String())
	bindDev := strings.TrimSpace(cfg.Section("").Key("bind_dev").String())
	ipNet := strings.TrimSpace(cfg.Section("").Key("ip_net").String())
	logLevel := strings.TrimSpace(cfg.Section("").Key("log_level").String())

	bufferSize := DefaultBufferSize
	if bufferSizeStr := strings.TrimSpace(cfg.Section("").Key("buffer_size").String()); len(bufferSizeStr) != 0 {
		if i, err := strconv.Atoi(bufferSizeStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for buffer_size configuration option, expected an integer", bufferSizeStr)
		} else {
			bufferSize = i
		}
	}

	numEventLoops := DefaultServerNumEventLoops
	if numEventLoopsStr := strings.TrimSpace(cfg.Section("").Key("num_event_loops").String()); len(numEventLoopsStr) != 0 {
		if i, err := strconv.Atoi(numEventLoopsStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for num_event_loops configuration option, expected an integer", numEventLoopsStr)
		} else {
			numEventLoops = i
		}
	}

	var socketRecvBuffer int64 = DefaultServerSocketRecvBufferSize
	if socketRecvBufferStr := strings.TrimSpace(cfg.Section("").Key("socket_recv_buffer").String()); len(socketRecvBufferStr) != 0 {
		if b, err := units.ParseStrictBytes(socketRecvBufferStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for socket_recv_buffer configuration option, expected byte unit", socketRecvBufferStr)
		} else {
			socketRecvBuffer = b
		}
	}

	var socketSendBuffer int64 = DefaultServerSocketSendBufferSize
	if socketSendBufferStr := strings.TrimSpace(cfg.Section("").Key("socket_send_buffer").String()); len(socketSendBufferStr) != 0 {
		if b, err := units.ParseStrictBytes(socketSendBufferStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for socket_send_buffer configuration option, expected byte unit", socketSendBufferStr)
		} else {
			socketSendBuffer = b
		}
	}

	out := Server{
		BindHost:         bindHost,
		BindDev:          bindDev,
		IPNet:            ipNet,
		NumEventLoops:    numEventLoops,
		SocketRecvBuffer: socketRecvBuffer,
		SocketSendBuffer: socketSendBuffer,
		BufferSize:       bufferSize,
		LogLevel:         DefaultServerLogLevel,
	}

	if logLevel != "" {
		if lvl, err := zerolog.ParseLevel(logLevel); nil != err {
			acceptedLevels := make([]string, len(allLogLevels))
			for i, lvl := range allLogLevels {
				acceptedLevels[i] = fmt.Sprintf("%q", lvl)
			}
			return nil, fmt.Errorf("config: invalid value of %q for log_level configuration option, accepted values are %s", logLevel, strings.Join(acceptedLevels, ", "))
		} else {
			out.LogLevel = lvl
		}
	}

	if err := out.validate(); nil != err {
		return nil, err
	}

	return &out, nil
}

func (s *Server) validate() error {
	if !isValidHostname(s.BindHost) {
		return errors.New("config: bind_host host is not a valid hostname")
	}

	if len(s.BindDev) == 0 {
		return errors.New("config: bind_dev is required")
	}

	if len(s.IPNet) == 0 {
		return errors.New("config: ip_net is required")
	} else if _, _, err := net.ParseCIDR(s.IPNet); nil != err {
		return errors.New("config: ip_net must be a valid CIDR notation")
	}

	if err := validateBufferSize(s.BufferSize); nil != err {
		return fmt.Errorf("config: buffer_size is invalid: %v", err)
	}

	return nil
}
