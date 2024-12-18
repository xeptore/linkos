package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"gopkg.in/ini.v1"
)

type Client struct {
	ServerAddr      string
	IP              string
	IncomingThreads int
	BufferSize      int
	MTU             uint32
	LogLevel        zerolog.Level
}

func (c *Client) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("server_address", c.ServerAddr).
		Str("ip", c.IP).
		Int("incoming_threads", c.IncomingThreads).
		Int("buffer_size", c.BufferSize).
		Uint32("mtu", c.MTU).
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

	incomingThreads := 4
	if incomingThreadsStr := strings.TrimSpace(cfg.Section("").Key("incoming_threads").String()); len(incomingThreadsStr) != 0 {
		i, err := strconv.Atoi(incomingThreadsStr)
		if nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for incoming_threads configuration option, expected an integer", incomingThreadsStr)
		} else {
			incomingThreads = i
		}
	}

	bufferSize := DefaultBufferSize
	if bufferSizeStr := strings.TrimSpace(cfg.Section("").Key("buffer_size").String()); len(bufferSizeStr) != 0 {
		if i, err := strconv.Atoi(bufferSizeStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for buffer_size configuration option, expected an integer", bufferSizeStr)
		} else {
			bufferSize = i
		}
	}

	var mtu uint32 = DefaultClientTunDeviceMTU
	if mtuStr := strings.TrimSpace(cfg.Section("").Key("mtu").String()); len(mtuStr) != 0 {
		if i, err := strconv.ParseUint(mtuStr, 10, 32); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for mtu configuration option, expected an integer", mtuStr)
		} else {
			mtu = uint32(i)
		}
	}

	ip := strings.TrimSpace(cfg.Section("").Key("ip").String())

	logLevel := strings.TrimSpace(cfg.Section("").Key("log_level").String())

	out := Client{
		ServerAddr:      serverAddr,
		IP:              ip,
		IncomingThreads: incomingThreads,
		BufferSize:      bufferSize,
		MTU:             mtu,
		LogLevel:        DefaultClientLogLevel,
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

	if c.IncomingThreads < 1 {
		return errors.New("config: incoming_threads must be greater than or equal to 1")
	}

	if len(c.ServerAddr) == 0 {
		return errors.New("config: server_address is required")
	} else if hostname, port, err := net.SplitHostPort(c.ServerAddr); nil != err {
		return errors.New("config: server_address must be a valid address")
	} else {
		if !isValidHostname(hostname) {
			return errors.New("config: server_address host is not a valid hostname")
		}
		if err := validatePort(port); nil != err {
			return fmt.Errorf("config: server_address port is not a valid port number: %v", err)
		}
	}

	if err := validateBufferSize(c.BufferSize); nil != err {
		return fmt.Errorf("config: buffer_size is invalid: %v", err)
	}

	if err := validateMTU(c.MTU); nil != err {
		return fmt.Errorf("config: mtu is invalid: %v", err)
	}

	return nil
}

// Hostname regex based on RFC 1123.
var validHostnameRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$`)

func isValidHostname(host string) bool {
	return validHostnameRegexp.MatchString(host)
}

func validatePort(port string) error {
	p, err := strconv.Atoi(port)
	if nil != err {
		return errors.New("must be a number")
	}
	if p < 0 || p > 65535 {
		return errors.New("out of range")
	}
	return nil
}

func validateBufferSize(n int) error {
	if n < 0 || n > 65535 {
		return errors.New("out of range")
	}
	return nil
}

func validateMTU(n uint32) error {
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
