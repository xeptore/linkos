//go:build windows && amd64

package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"

	"github.com/xeptore/linkos"
	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/tun"
)

func main() {
	if err := run(); nil != err {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stdout, "Press enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Press enter to exit...")
	fmt.Scanln()
}

func run() (err error) {
	logger, err := log.New()
	if nil != err {
		return fmt.Errorf("failed to create logger: %v\n", err)
	}
	defer func() {
		if syncErr := logger.Sync(); nil != syncErr {
			err = fmt.Errorf("failed to sync logger: %v\n", syncErr)
		}
	}()

	cfg, err := config.Load(logger)
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile("linkos.ini", linkos.ConfigFileTemplateContent, 0o0600); nil != err {
				return fmt.Errorf("config file was not found. Tried creating a template config file but did not succeeded.")
			}
			return fmt.Errorf("config file was not found. A template is created with name linkos.ini. You should fill with proper values.")
		}
		return fmt.Errorf("failed to load config file", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	logger.Debug("Initializing VPN tunnel")
	t, err := tun.New(logger.With(zap.String("module", "tune")))
	if nil != err {
		return fmt.Errorf("failed to create VPN tunnel", err)
	}
	logger.Debug("VPN tunnel initialized")

	logger.Debug("Assigning IP address to tunnel adapter", zap.String("ip", cfg.IP))
	if err := t.AssignIPv4(cfg.IP); nil != err {
		return fmt.Errorf("failed to assign IP address to tunnel adapter: %v", err)
	}
	logger.Debug("Assigned IP address to tunnel adapter")

	// assign gateway
	// add routes
	// see:
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L117
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L130-L149
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L125
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L107
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L71

	logger.Debug("Bringing up VPN tunnel")
	packets, err := t.Up(ctx)
	if nil != err {
		return fmt.Errorf("failed to bring up VPN interface", err)
	}
	defer func() {
		logger.Debug("Shutting down VPN tunnel")
		if downErr := t.Down(); nil != downErr {
			err = fmt.Errorf("failed to properly shutdown VPN tunnel", downErr)
		}
		logger.Debug("VPN tunnel successfully shutdown")
	}()
	logger.Debug("VPN tunnel is up")

	logger.Debug("Resolving server address", zap.String("address", cfg.ServerAddr))
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if nil != err {
		return fmt.Errorf("failed to resolve server address", err)
	}
	logger.Debug("Resolved server address")

	logger.Debug("Dialing server")
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if nil != err {
		return fmt.Errorf("failed to connect to server", err)
	}
	defer func() {
		logger.Debug("Closing tunnel connection")
		if closeErr := conn.Close(); nil != closeErr {
			if errors.Is(closeErr, net.ErrClosed) {
				logger.Debug("Tunnel connection has already been closed")
				return
			}
			err = fmt.Errorf("failed to properly close tunnel connection", closeErr)
		}
		logger.Debug("Tunnel connection has been closed successfully")
	}()
	context.AfterFunc(ctx, func() {
		logger.Debug("Closing tunnel connection due to context cancellation")
		if closeErr := conn.Close(); nil != closeErr {
			err = fmt.Errorf("failed to close tunnel connection", closeErr)
			return
		}
		logger.Debug("Tunnel connection has been closed successfully")
	})

	logger.Debug("Spawning worker goroutines")
	var wg sync.WaitGroup
	wg.Add(2)

	client := Client{
		t:       t,
		conn:    conn,
		packets: packets,
		logger:  logger.With(zap.String("module", "client")),
	}

	go client.handleOutgoing(ctx, &wg)
	go client.handleIncoming(&wg)

	logger.Debug("Waiting for close signal")
	<-ctx.Done()
	logger.Debug("Close signal received. Waiting for worker goroutines to return")
	wg.Wait()
	logger.Debug("Worker goroutines returned")
	logger.Warn("Exiting")
	return nil
}

type Client struct {
	t       *tun.Tun
	conn    *net.UDPConn
	packets tun.Packets
	logger  *zap.Logger
}

func (c *Client) handleOutgoing(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	logger := c.logger.With(zap.String("worker", "outgoing"))

	for {
		select {
		case <-ctx.Done():
			logger.Debug("Closing due to parent context closure")
			return
		case packet := <-c.packets:
			p, err := packet.Get()
			if nil != err {
				logger.Error("Error reading from TUN device", zap.Error(err))
				return
			}

			if ok, err := filterOutgoingPacket(logger, p); nil != err {
				logger.Debug("Failed to parse packet for filtering", zap.Error(err))
			} else if !ok {
				logger.Debug("Dropping packet")
			}

			n, err := c.conn.Write(p)
			if nil != err {
				logger.Error("Error sending data to server", zap.Error(err))
				return
			}
			logger.Debug("Outgoing packet has been written to tunnel connection", zap.Int("bytes", n))
		}
	}
}

func (c *Client) handleIncoming(wg *sync.WaitGroup) {
	defer wg.Done()
	logger := c.logger.With(zap.String("worker", "incoming"))

	const bufferSize = 2048
	buffer := make([]byte, bufferSize)
	for {
		n, _, err := c.conn.ReadFromUDP(buffer)
		if nil != err && !errors.Is(err, net.ErrClosed) {
			logger.Error("Error receiving data from server tunnel", zap.Error(err))
			return
		}
		logger.Debug("Received bytes from server tunnel", zap.Int("bytes", n))

		n, err = c.t.Write(buffer[:n])
		if nil != err {
			logger.Error("Error writing to TUN device", zap.Error(err))
			return
		}
		logger.Debug("Incoming packet has been written to TUN device", zap.Int("bytes", n))
	}
}

func determineVersion(packet []byte) (int, error) {
	if len(packet) < 1 {
		return 0, os.ErrInvalid
	}

	return int(packet[0] >> 4), nil
}

func filterOutgoingPacket(logger *zap.Logger, p tun.Packet) (bool, error) {
	v, err := determineVersion(p)
	if nil != err {
		return false, err
	}

	var decoder gopacket.Decoder
	switch v {
	case 6:
		logger.Debug("Skipping IPv6 packet")
		return false, nil
	case 4:
		decoder = layers.LayerTypeIPv4
	default:
		panic(fmt.Sprintf("unexpected packet version: %d", v))
	}

	packet := gopacket.NewPacket(p, decoder, gopacket.DecodeOptions{Lazy: true, NoCopy: true}) //nolint:exhaustruct
	if err := packet.ErrorLayer(); nil != err {
		return false, fmt.Errorf("failed to parse packet with length %d: %v", len(p), err.Error())
	}

	if layer := packet.Layer(layers.LayerTypeICMPv4); nil != layer {
		icmp := layer.(*layers.ICMPv4)
		logger.Debug("Detected ICMPv4 packet", zap.Uint16("seq", icmp.Seq), zap.Uint16("id", icmp.Id), zap.Int("payload_len", len(icmp.Payload)))
		return true, nil
	}

	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		logger.Debug("Detected IPv4 packet", zap.String("src", ip.SrcIP.String()), zap.String("dst", ip.DstIP.String()))

		if layer := packet.TransportLayer(); nil != layer {
			if layer, ok := layer.(*layers.UDP); ok {
				logger.Debug("Detected UDP packet", zap.String("src_port", layer.SrcPort.String()), zap.String("dst_port", layer.DstPort.String()))
				if layer.DstPort == 5353 && layer.SrcPort == 5353 && ip.DstIP.String() == "224.0.0.251" { // mDNS
					logger.Debug("Skipping mDNS packet")
					return false, nil
				}
				return true, nil
			}
		}
	}

	return false, nil
}
