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
	IP               net.IP
	IsHost           bool
	RingSize         uint32
	BufferSize       int
	SocketRecvBuffer int
	SocketSendBuffer int
	MTU              uint32
	LogLevel         zerolog.Level
	FileLogLevel     zerolog.Level
}

func (c *Client) LogDict() *zerolog.Event {
	return zerolog.
		Dict().
		Str("server_host", c.ServerHost).
		Str("ip", c.IP.String()).
		Bool("is_host", c.IsHost).
		Int("buffer_size", c.BufferSize).
		Int("socket_send_buffer", c.SocketSendBuffer).
		Int("socket_recv_buffer", c.SocketRecvBuffer).
		Uint32("mtu", c.MTU).
		Uint32("ring_size", c.RingSize).
		Str("log_level", c.LogLevel.String()).
		Str("file_log_level", c.FileLogLevel.String())
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
	if !isValidHostname(serverHost) {
		return nil, errors.New("config: server_host host is not a valid hostname")
	}

	var ringSize uint32 = DefaultTunRingSize
	if ringSizeStr := strings.TrimSpace(cfg.Section("").Key("ring_size").String()); len(ringSizeStr) != 0 {
		if i, err := strconv.ParseUint(ringSizeStr, 10, 32); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for ring_size configuration option, expected an integer", ringSizeStr)
		} else if err := validateRingSizeExp(uint32(i)); nil != err {
			return nil, fmt.Errorf("config: ring_size is invalid: %v", err)
		} else {
			ringSize = uint32(i)
		}
	}

	bufferSize := DefaultBufferSize
	if bufferSizeStr := strings.TrimSpace(cfg.Section("").Key("buffer_size").String()); len(bufferSizeStr) != 0 {
		if i, err := strconv.Atoi(bufferSizeStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for buffer_size configuration option, expected an integer", bufferSizeStr)
		} else if err := validateBufferSize(i); nil != err {
			return nil, fmt.Errorf("config: buffer_size is invalid: %v", err)
		} else {
			bufferSize = i
		}
	}

	socketSendBuffer := int(DefaultClientSocketSendBuffer)
	if socketSendBufferStr := strings.TrimSpace(cfg.Section("").Key("socket_send_buffer").String()); len(socketSendBufferStr) != 0 {
		if i, err := units.ParseStrictBytes(socketSendBufferStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for socket_send_buffer configuration option, expected byte size", socketSendBufferStr)
		} else {
			socketSendBuffer = int(i)
		}
	}

	socketRecvBuffer := int(DefaultClientSocketRecvBuffer)
	if socketRecvBufferStr := strings.TrimSpace(cfg.Section("").Key("socket_recv_buffer").String()); len(socketRecvBufferStr) != 0 {
		if i, err := units.ParseStrictBytes(socketRecvBufferStr); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for socket_recv_buffer configuration option, expected byte size", socketRecvBufferStr)
		} else {
			socketRecvBuffer = int(i)
		}
	}

	var mtu uint32 = DefaultClientTunDeviceMTU
	if mtuStr := strings.TrimSpace(cfg.Section("").Key("mtu").String()); len(mtuStr) != 0 {
		if i, err := strconv.ParseUint(mtuStr, 10, 32); nil != err {
			return nil, fmt.Errorf("config: invalid value of %q for mtu configuration option, expected an integer", mtuStr)
		} else if err := validateMTU(uint32(i)); nil != err {
			return nil, fmt.Errorf("config: mtu is invalid: %v", err)
		} else {
			mtu = uint32(i)
		}
	}

	ip := strings.TrimSpace(cfg.Section("").Key("ip").String())
	if len(ip) == 0 {
		return nil, errors.New("config: ip is required")
	} else if ip := net.ParseIP(ip); ip == nil {
		return nil, errors.New("config: ip is not a valid IP address")
	}

	var isHost bool
	if isHostStr := strings.TrimSpace(cfg.Section("").Key("is_host").String()); len(isHostStr) != 0 {
		switch isHostStr {
		case "0":
		case "1":
			isHost = true
		default:
			return nil, errors.New("config: is_host can only be 0 or 1")
		}
	}

	logLevel := DefaultClientLogLevel
	if logLevelStr := strings.TrimSpace(cfg.Section("").Key("log_level").String()); logLevelStr != "" {
		if lvl, err := zerolog.ParseLevel(logLevelStr); nil != err {
			acceptedLevels := make([]string, len(allLogLevels))
			for i, lvl := range allLogLevels {
				acceptedLevels[i] = fmt.Sprintf("%q", lvl)
			}
			return nil, fmt.Errorf("config: invalid value of %q for log_level configuration option, accepted values are %s", logLevelStr, strings.Join(acceptedLevels, ", "))
		} else {
			logLevel = lvl
		}
	}

	fileLogLevel := zerolog.Disabled
	if logLevelStr := strings.TrimSpace(cfg.Section("").Key("file_log_level").String()); logLevelStr != "" {
		if lvl, err := zerolog.ParseLevel(logLevelStr); nil != err {
			acceptedLevels := make([]string, len(allLogLevels))
			for i, lvl := range allLogLevels {
				acceptedLevels[i] = fmt.Sprintf("%q", lvl)
			}
			return nil, fmt.Errorf("config: invalid value of %q for file_log_level configuration option, accepted values are %s", logLevelStr, strings.Join(acceptedLevels, ", "))
		} else {
			fileLogLevel = lvl
		}
	}

	out := Client{
		ServerHost:       serverHost,
		IP:               net.ParseIP(ip).To4(),
		IsHost:           isHost,
		RingSize:         ringSize,
		BufferSize:       bufferSize,
		SocketRecvBuffer: socketRecvBuffer,
		SocketSendBuffer: socketSendBuffer,
		MTU:              mtu,
		LogLevel:         logLevel,
		FileLogLevel:     fileLogLevel,
	}

	return &out, nil
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
