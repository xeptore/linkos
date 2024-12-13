package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

type Client struct {
	ServerAddr string
	IP         string
	LogLevel   logrus.Level
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
		LogLevel:   logrus.TraceLevel,
	}

	if logLevel != "" {
		if lvl, err := logrus.ParseLevel(logLevel); nil != err {
			acceptedLevels := make([]string, len(logrus.AllLevels))
			for i, lvl := range logrus.AllLevels {
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

func (c Client) validate() error {
	if len(c.IP) == 0 {
		return errors.New("config: ip is required")
	} else if ip := net.ParseIP(c.IP); ip == nil {
		return errors.New("config: ip is not a valid IP address")
	}

	if len(c.ServerAddr) == 0 {
		return errors.New("config: server_address is required")
	} else if _, err := net.ResolveUDPAddr("udp", c.ServerAddr); nil != err {
		return errors.New("config: server_address must be a valid address")
	}

	return nil
}

type Server struct {
	BindAddr   string
	SubnetCIDR string
	BufferSize int
	LogLevel   logrus.Level
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
	subnetCIDR := strings.TrimSpace(cfg.Section("").Key("subnet_cidr").String())
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
		SubnetCIDR: subnetCIDR,
		BufferSize: bufferSize,
		LogLevel:   logrus.TraceLevel,
	}

	if logLevel != "" {
		if lvl, err := logrus.ParseLevel(logLevel); nil != err {
			acceptedLevels := make([]string, len(logrus.AllLevels))
			for i, lvl := range logrus.AllLevels {
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

func (s Server) validate() error {
	if len(s.BindAddr) == 0 {
		return errors.New("config: bind_address is required")
	} else if _, err := net.ResolveUDPAddr("udp", s.BindAddr); nil != err {
		return errors.New("config: bind_address must be a valid address")
	}

	if len(s.SubnetCIDR) == 0 {
		return errors.New("config: subnet_cidr is required")
	} else if _, _, err := net.ParseCIDR(s.SubnetCIDR); nil != err {
		return errors.New("config: subnet_cidr must be a valid CIDR notation")
	}

	return nil
}
