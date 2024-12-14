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

type Client struct {
	ServerAddr string
	IP         string
	LogLevel   zerolog.Level
}

func (c *Client) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("server_address", c.ServerAddr).
		Str("ip", c.IP).
		Str("log_level", c.LogLevel.String())
}

func LoadClient(filename string) (*Client, error) {
	cfg, err := ini.Load(filename)
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("config: failed to load: %v", err)
	}

	serverAddr := strings.TrimSpace(cfg.Section("").Key("server_address").String())
	tunIP := strings.TrimSpace(cfg.Section("").Key("ip").String())
	logLevel := strings.TrimSpace(cfg.Section("").Key("log_level").String())

	out := Client{
		ServerAddr: serverAddr,
		IP:         tunIP,
		LogLevel:   DefaultClientLogLevel,
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

func (c *Client) validate() error {
	if len(c.IP) == 0 {
		return errors.New("config: ip is required")
	} else if ip := net.ParseIP(c.IP); ip == nil {
		return errors.New("config: ip is not a valid IP address")
	}

	if len(c.ServerAddr) == 0 {
		return errors.New("config: server_address is required")
	} else if _, _, err := net.SplitHostPort(c.ServerAddr); nil != err {
		return errors.New("config: server_address must be a valid address")
	}

	return nil
}

type Server struct {
	BindAddr   string
	IPNet      string
	BufferSize int
	LogLevel   zerolog.Level
}

func (s *Server) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("bind_address", s.BindAddr).
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
	ipNet := strings.TrimSpace(cfg.Section("").Key("ip_net").String())
	logLevel := strings.TrimSpace(cfg.Section("").Key("log_level").String())
	bufferSize := DefaultServerBufferSize
	bufferSizeStr := strings.TrimSpace(cfg.Section("").Key("buffer_size").String())
	if len(bufferSizeStr) != 0 {
		if i, err := strconv.Atoi(bufferSizeStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for buffer_size configuration option, expected an integer", bufferSizeStr)
		} else {
			bufferSize = i
		}
	}

	out := Server{
		BindAddr:   bindAddr,
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

	if len(s.IPNet) == 0 {
		return errors.New("config: ip_net is required")
	} else if _, _, err := net.ParseCIDR(s.IPNet); nil != err {
		return errors.New("config: ip_net must be a valid CIDR notation")
	}

	return nil
}
