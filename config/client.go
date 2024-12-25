//go:build windows && amd64

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
	ServerHost  string
	IP          string
	RingSizeExp uint32
	BufferSize  int
	MTU         uint32
	LogLevel    zerolog.Level
}

func (c *Client) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("server_host", c.ServerHost).
		Str("ip", c.IP).
		Int("buffer_size", c.BufferSize).
		Uint32("mtu", c.MTU).
		Uint32("ring_size_exp", c.RingSizeExp).
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

	serverHost := strings.TrimSpace(cfg.Section("").Key("server_host").String())

	var ringSizeExp uint32 = DefaultTunRingSizePower
	if ringSizeExpStr := strings.TrimSpace(cfg.Section("").Key("ring_size_exp").String()); len(ringSizeExpStr) != 0 {
		if i, err := strconv.ParseUint(ringSizeExpStr, 10, 32); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for ring_size_exp configuration option, expected an integer", ringSizeExpStr)
		} else {
			ringSizeExp = uint32(i)
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
		ServerHost:  serverHost,
		IP:          ip,
		RingSizeExp: ringSizeExp,
		BufferSize:  bufferSize,
		MTU:         mtu,
		LogLevel:    DefaultClientLogLevel,
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

	if !isValidHostname(c.ServerHost) {
		return errors.New("config: server_host host is not a valid hostname")
	}

	if err := validateBufferSize(c.BufferSize); nil != err {
		return fmt.Errorf("config: buffer_size is invalid: %v", err)
	}

	if err := validateMTU(c.MTU); nil != err {
		return fmt.Errorf("config: mtu is invalid: %v", err)
	}

	if err := validateRingSizeExp(c.RingSizeExp); nil != err {
		return fmt.Errorf("config: ring_size_exp is invalid: %v", err)
	}

	return nil
}

func validateRingSizeExp(n uint32) error {
	if n < 17 || n > 26 {
		return fmt.Errorf("must be in range %d - %d including", 17, 26)
	}

	return nil
}

func validateMTU(n uint32) error {
	if n > 65535 {
		return errors.New("out of range")
	}
	return nil
}
