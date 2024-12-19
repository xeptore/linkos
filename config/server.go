package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

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
	BindAddr   string
	BindDev    string
	IPNet      string
	BufferSize int
	LogLevel   zerolog.Level
}

func (s *Server) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("bind_address", s.BindAddr).
		Str("bind_dev", s.BindDev).
		Str("ip_net", s.IPNet).
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

	bindAddr := strings.TrimSpace(cfg.Section("").Key("bind_address").String())
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

	out := Server{
		BindAddr:   bindAddr,
		BindDev:    bindDev,
		IPNet:      ipNet,
		BufferSize: bufferSize,
		LogLevel:   DefaultServerLogLevel,
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
	if len(s.BindAddr) == 0 {
		return errors.New("config: bind_address is required")
	} else if _, err := net.ResolveUDPAddr("udp", s.BindAddr); nil != err {
		return errors.New("config: bind_address must be a valid address")
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
