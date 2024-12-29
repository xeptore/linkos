//go:build windows && amd64

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

type Client struct {
	ServerHost       string
	IP               string
	RingSize         uint32
	BufferSize       int
	SocketRecvBuffer int64
	SocketSendBuffer int64
	MTU              uint32
	LogLevel         zerolog.Level
}

func (c *Client) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("server_host", c.ServerHost).
		Str("ip", c.IP).
		Int("buffer_size", c.BufferSize).
		Int64("socket_send_buffer", c.SocketSendBuffer).
		Int64("socket_recv_buffer", c.SocketRecvBuffer).
		Uint32("mtu", c.MTU).
		Uint32("ring_size", c.RingSize).
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

	var ringSizeExp uint32 = DefaultTunRingSize
	if ringSizeExpStr := strings.TrimSpace(cfg.Section("").Key("ring_size").String()); len(ringSizeExpStr) != 0 {
		if i, err := strconv.ParseUint(ringSizeExpStr, 10, 32); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for ring_size configuration option, expected an integer", ringSizeExpStr)
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

	var sendBuffer int64 = DefaultClientSendBuffer
	if socketSendBufferStr := strings.TrimSpace(cfg.Section("").Key("socket_send_buffer").String()); len(socketSendBufferStr) != 0 {
		if i, err := units.ParseStrictBytes(socketSendBufferStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for socket_send_buffer configuration option, expected byte size", socketSendBufferStr)
		} else {
			sendBuffer = i
		}
	}

	var socketRecvBuffer int64 = DefaultClientSocketRecvBuffer
	if socketRecvBufferStr := strings.TrimSpace(cfg.Section("").Key("socket_recv_buffer").String()); len(socketRecvBufferStr) != 0 {
		if i, err := units.ParseStrictBytes(socketRecvBufferStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for socket_recv_buffer configuration option, expected byte size", socketRecvBufferStr)
		} else {
			socketRecvBuffer = i
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
		ServerHost:       serverHost,
		IP:               ip,
		RingSize:         ringSizeExp,
		BufferSize:       bufferSize,
		SocketRecvBuffer: socketRecvBuffer,
		SocketSendBuffer: sendBuffer,
		MTU:              mtu,
		LogLevel:         DefaultClientLogLevel,
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

	if err := validateRingSizeExp(c.RingSize); nil != err {
		return fmt.Errorf("config: ring_size is invalid: %v", err)
	}

	return nil
}

func validateRingSizeExp(n uint32) error {
	if n < 1 || n > 10 {
		return fmt.Errorf("must be in range %d - %d including", 1, 10)
	}

	return nil
}

func validateMTU(n uint32) error {
	if n > 65535 {
		return errors.New("out of range")
	}
	return nil
}
