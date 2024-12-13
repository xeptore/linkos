//go:build windows && amd64

package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/tun"
	"github.com/xeptore/linkos/update"
)

func init() {
	// Disable default standard logger to discard internal wintun log messages
	stdlog.SetOutput(io.Discard)
	stdlog.SetFlags(0)
}

var (
	Version        = "dev"
	configFileName = "config.ini"
	errSigTrapped  = context.DeadlineExceeded
)

func waitForEnter() {
	fmt.Fprintln(os.Stdout, "Press enter to exit...")
	bufio.NewReader(io.LimitReader(os.Stdin, 1)).ReadBytes('\n') //nolint:errcheck
}

func main() {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		signal.Stop(c)
		cancel(errSigTrapped)
	}()

	logger, err := log.New()
	if nil != err {
		fmt.Fprintf(os.Stderr, "Error: failed to create logger: %v\n", err)
		waitForEnter()
		return
	}
	logger = logger.With().Str("version", Version).Logger()

	if err := run(ctx, logger); nil != err {
		logger.Error().Err(err).Msg("Failed to run the application")
		waitForEnter()
		return
	}
	if errors.Is(context.Cause(ctx), errSigTrapped) {
		logger.Warn().Msg("Exiting due to signal")
		time.Sleep(1 * time.Second)
		return
	}
	waitForEnter()
}

func run(ctx context.Context, logger zerolog.Logger) (err error) {
	cfg, err := config.LoadClient(configFileName)
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(configFileName, config.ClientConfigTemplate, 0o0600); nil != err {
				return fmt.Errorf("config: file was not found. Tried creating a template file but did not succeeded: %v", err)
			}
			return fmt.Errorf("config: file was not found. A template is created with name linkos.ini. You should fill with proper values: %v", err)
		}
		return fmt.Errorf("config: failed to load: %v", err)
	}
	logger = logger.Level(cfg.LogLevel)

	if Version != "dev" {
		logger.Trace().Str("current_version", Version).Msg("Checking for new releases")
		if exists, err := update.NewerVersionExists(ctx, Version); nil != err {
			logger.Error().Err(err).Msg("Failed to check for newer version existence. Make sure you have internet access.")
		} else if exists {
			logger.Error().Msg("Newer version exists. Download it from: https://github.com/xeptore/linkos/releases/latest")
			return nil
		}
	}

	logger.Trace().Msg("Initializing VPN tunnel")
	t, err := tun.New(logger.With().Str("module", "tune").Logger())
	if nil != err {
		return fmt.Errorf("tun: failed to create: %v", err)
	}
	logger.Info().Msg("VPN tunnel initialized")

	logger.Trace().Str("ip", cfg.IP).Msg("Assigning IP address to tunnel adapter")
	if err := t.AssignIPv4(cfg.IP); nil != err {
		return fmt.Errorf("tun: failed to assign IP address: %v", err)
	}
	logger.Info().Str("ip", cfg.IP).Msg("Assigned IP address to tunnel adapter")

	// assign gateway
	// add routes
	// see:
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L117
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L130-L149
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L125
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L107
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L71

	logger.Trace().Msg("Bringing up VPN tunnel")
	packets, err := t.Up(ctx)
	if nil != err {
		return fmt.Errorf("tun: failed to bring up interface: %v", err)
	}
	defer func() {
		logger.Trace().Msg("Shutting down VPN tunnel")
		if downErr := t.Down(); nil != downErr {
			err = fmt.Errorf("tun: failed to properly shutdown: %v", downErr)
		}
		logger.Trace().Msg("VPN tunnel successfully shutdown")
	}()
	logger.Info().Msg("VPN tunnel is up")

	logger.Trace().Str("address", cfg.ServerAddr).Msg("Resolving server address")
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if nil != err {
		return fmt.Errorf("tunnel: failed to resolve server address: %v", err)
	}
	logger.Trace().Msg("Resolved server address")

	logger.Trace().Msg("Dialing server")
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if nil != err {
		return fmt.Errorf("tunnel: failed to connect to server: %v", err)
	}
	if err := conn.SetReadBuffer(config.DefaultClientBufferSize); nil != err {
		return fmt.Errorf("tunnel: failed to set read buffer: %v", err)
	}
	if err := conn.SetWriteBuffer(config.DefaultClientBufferSize); nil != err {
		return fmt.Errorf("tunnel: failed to set write buffer: %v", err)
	}
	defer func() {
		logger.Trace().Msg("Closing tunnel connection")
		if closeErr := conn.Close(); nil != closeErr {
			if errors.Is(closeErr, net.ErrClosed) {
				logger.Trace().Msg("Tunnel connection has already been closed")
				return
			}
			err = fmt.Errorf("tunnel: failed to properly close connection: %v", closeErr)
		}
		logger.Info().Msg("Tunnel connection has been closed")
	}()
	context.AfterFunc(ctx, func() {
		logger.Trace().Msg("Closing tunnel connection due to context cancellation")
		if closeErr := conn.Close(); nil != closeErr {
			err = fmt.Errorf("tunnel: failed to properly close connection due to context cancellation: %v", closeErr)
			return
		}
		logger.Info().Msg("Tunnel connection has been closed")
	})

	logger.Trace().Msg("Spawning worker goroutines")
	var wg sync.WaitGroup
	wg.Add(2)

	client := Client{
		t:       t,
		conn:    conn,
		packets: packets,
		logger:  logger.With().Str("module", "client").Logger(),
	}

	logger.WithLevel(log.NoLevel).Msg("Starting VPN client")

	go client.handleOutgoing(ctx, &wg)
	go client.handleIncoming(&wg)

	logger.Trace().Msg("Waiting for close signal")
	<-ctx.Done()
	logger.Trace().Msg("Close signal received. Waiting for worker goroutines to return")
	wg.Wait()
	logger.Trace().Msg("Worker goroutines returned")
	return nil
}

type Client struct {
	t       *tun.Tun
	conn    *net.UDPConn
	packets tun.Packets
	logger  zerolog.Logger
}

func (c *Client) handleOutgoing(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	logger := c.logger.With().Str("worker", "outgoing").Logger()

	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Closing due to parent context closure")
			return
		case packet := <-c.packets:
			p, err := packet.Get()
			if nil != err {
				logger.Error().Err(err).Msg("Error reading from TUN device")
				return
			}

			if ok, err := filterOutgoingPacket(logger, p); nil != err {
				logger.Debug().Err(err).Msg("Failed to filter packet")
			} else if !ok {
				logger.Trace().Msg("Dropping packet")
			}

			n, err := c.conn.Write(p)
			if nil != err {
				logger.Error().Err(err).Msg("Error sending data to server")
				return
			}
			logger.Trace().Int("bytes", n).Msg("Outgoing packet has been written to tunnel connection")
		}
	}
}

func (c *Client) handleIncoming(wg *sync.WaitGroup) {
	defer wg.Done()
	logger := c.logger.With().Str("worker", "incoming").Logger()

	buffer := make([]byte, config.DefaultClientBufferSize)
	for {
		n, _, err := c.conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				logger.Trace().Msg("Ending server tunnel worker due to connection closure")
			} else {
				logger.Error().Err(err).Msg("Error receiving data from server tunnel")
			}
			return
		}
		logger.Trace().Int("bytes", n).Msg("Received bytes from server tunnel")

		n, err = c.t.Write(buffer[:n])
		if nil != err {
			logger.Error().Err(err).Msg("Error writing to TUN device")
			return
		}
		logger.Trace().Int("bytes", n).Msg("Incoming packet has been written to TUN device")
	}
}

func determineVersion(packet []byte) (int, error) {
	if len(packet) < 1 {
		return 0, os.ErrInvalid
	}

	return int(packet[0] >> 4), nil
}

func filterOutgoingPacket(logger zerolog.Logger, p tun.Packet) (bool, error) {
	v, err := determineVersion(p)
	if nil != err {
		return false, err
	}

	var decoder gopacket.Decoder
	switch v {
	case 6:
		logger.Trace().Msg("Skipping IPv6 packet")
		return false, nil
	case 4:
		decoder = layers.LayerTypeIPv4
	default:
		panic(fmt.Sprintf("unexpected packet version: %d", v))
	}

	packet := gopacket.NewPacket(p, decoder, gopacket.DecodeOptions{Lazy: true, NoCopy: true}) //nolint:exhaustruct
	if err := packet.ErrorLayer(); nil != err {
		return false, fmt.Errorf("tunnel: failed to parse packet with length %d: %v", len(p), err.Error())
	}

	if layer := packet.Layer(layers.LayerTypeICMPv4); nil != layer {
		icmp := layer.(*layers.ICMPv4)
		logger.Trace().Uint16("id", icmp.Id).Uint16("seq", icmp.Seq).Int("payload_len", len(icmp.Payload)).Msg("Detected ICMPv4 packet")
		return true, nil
	}

	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		logger := logger.With().Str("src", ip.SrcIP.String()).Str("dst", ip.DstIP.String()).Logger()
		logger.Trace().Msg("Detected IPv4 packet")

		if layer := packet.TransportLayer(); nil != layer {
			if layer, ok := layer.(*layers.UDP); ok {
				logger := logger.With().Str("src_port", layer.SrcPort.String()).Str("dst_port", layer.DstPort.String()).Logger()
				logger.Trace().Msg("Detected UDP packet")
				if layer.DstPort == 5353 && layer.SrcPort == 5353 && ip.DstIP.String() == "224.0.0.251" { // mDNS
					logger.Trace().Msg("Skipping mDNS packet")
					return false, nil
				}
				return true, nil
			}
		}
	}

	return false, nil
}
