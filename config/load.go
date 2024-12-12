package config

import (
	"errors"
	"fmt"
	"net"
	"os"
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
		return nil, fmt.Errorf("config: failed to load config file: %v", err)
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
	if ip := net.ParseIP(c.IP); ip == nil {
		return errors.New("config: ip is not a valid IP address")
	}

	if _, err := net.ResolveUDPAddr("udp", c.ServerAddr); nil != err {
		return errors.New("config: server_address must be a valid address")
	}

	return nil
}
