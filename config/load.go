package config

import (
	"errors"
	"fmt"
	"net"
	"os"

	"go.uber.org/zap"
	"gopkg.in/ini.v1"
)

type Config struct {
	ServerAddr string
	IP         string
}

func Load(logger *zap.Logger) (*Config, error) {
	cfg, err := ini.Load("linkos.ini")
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("failed to load config file: %v", err)
	}

	serverAddr := cfg.Section("").Key("server_address").String()
	tunIP := cfg.Section("").Key("ip").String()

	out := Config{
		ServerAddr: serverAddr,
		IP:         tunIP,
	}

	if err := out.validate(); nil != err {
		return nil, err
	}

	return &out, nil
}

func (c Config) validate() error {
	if ip := net.ParseIP(c.IP); ip == nil {
		return fmt.Errorf("ip is not a valid IP address")
	}

	if _, err := net.ResolveUDPAddr("udp", c.ServerAddr); nil != err {
		return fmt.Errorf("server_address must be a valid address")
	}

	return nil
}
