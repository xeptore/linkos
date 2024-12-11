//go:build windows && amd64

package main

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"

	"github.com/xeptore/linkos"
	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/tun"
)

func waitForEnter() {
	fmt.Fprintln(os.Stdout, "Press enter to exit...")
	bufio.NewReader(io.LimitReader(os.Stdin, 1)).ReadBytes('\n') //nolint:errcheck
}

func main() {
	logger, err := log.New()
	if nil != err {
		fmt.Fprintf(os.Stderr, "Error: failed to create logger: %v\n", err)
		waitForEnter()
		os.Exit(10)
	}

	if err := run(logger); nil != err {
		logger.WithError(err).Error("Failed to run the client")
		waitForEnter()
		os.Exit(1)
	}
	waitForEnter()
}

func run(logger *logrus.Logger) (err error) {
	cfg, err := config.Load()
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile("linkos.ini", linkos.ConfigFileTemplateContent, 0o0600); nil != err {
				return fmt.Errorf("config file was not found. Tried creating a template config file but did not succeeded: %v", err)
			}
			return fmt.Errorf("config file was not found. A template is created with name linkos.ini. You should fill with proper values: %v", err)
		}
		return fmt.Errorf("failed to load config file: %v", err)
	}
	logger.SetLevel(cfg.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT, syscall.SIGKILL)
	defer stop()

	logger.Trace("Initializing VPN tunnel")
	t, err := tun.New(logger.WithField("module", "tune").Dup().Logger)
	if nil != err {
		return fmt.Errorf("failed to create VPN tunnel: %v", err)
	}
	logger.Info("VPN tunnel initialized")

	logger.WithField("ip", cfg.IP).Trace("Assigning IP address to tunnel adapter")
	if err := t.AssignIPv4(cfg.IP); nil != err {
		return fmt.Errorf("failed to assign IP address to tunnel adapter: %v", err)
	}
	logger.Info("Assigned IP address to tunnel adapter")

	// assign gateway
	// add routes
	// see:
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L117
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L130-L149
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L125
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L107
	//     https://github.com/SagerNet/sing-tun/blob/b599269a3c8536f49dd914db838951dfcce99e5c/tun_windows.go#L71

	logger.Trace("Bringing up VPN tunnel")
	packets, err := t.Up(ctx)
	if nil != err {
		return fmt.Errorf("failed to bring up VPN interface: %v", err)
	}
	defer func() {
		logger.Trace("Shutting down VPN tunnel")
		if downErr := t.Down(); nil != downErr {
			err = fmt.Errorf("failed to properly shutdown VPN tunnel: %v", downErr)
		}
		logger.Trace("VPN tunnel successfully shutdown")
	}()
	logger.Info("VPN tunnel is up")

	logger.WithField("address", cfg.ServerAddr).Trace("Resolving server address")
	serverAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if nil != err {
		return fmt.Errorf("failed to resolve server address: %v", err)
	}
	logger.Trace("Resolved server address")

	logger.Trace("Dialing server")
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if nil != err {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer func() {
		logger.Trace("Closing tunnel connection")
		if closeErr := conn.Close(); nil != closeErr {
			if errors.Is(closeErr, net.ErrClosed) {
				logger.Trace("Tunnel connection has already been closed")
				return
			}
			err = fmt.Errorf("failed to properly close tunnel connection: %v", closeErr)
		}
		logger.Info("Tunnel connection has been closed")
	}()
	context.AfterFunc(ctx, func() {
		logger.Trace("Closing tunnel connection due to context cancellation")
		if closeErr := conn.Close(); nil != closeErr {
			err = fmt.Errorf("failed to close tunnel connection: %v", closeErr)
			return
		}
		logger.Info("Tunnel connection has been closed")
	})

	logger.Trace("Spawning worker goroutines")
	var wg sync.WaitGroup
	wg.Add(2)

	client := Client{
		t:       t,
		conn:    conn,
		packets: packets,
		logger:  logger.WithField("module", "client").Dup().Logger,
	}

	go client.handleOutgoing(ctx, &wg)
	go client.handleIncoming(&wg)

	logger.Trace("Waiting for close signal")
	<-ctx.Done()
	logger.Trace("Close signal received. Waiting for worker goroutines to return")
	wg.Wait()
	logger.Trace("Worker goroutines returned")
	return nil
}

type Client struct {
	t       *tun.Tun
	conn    *net.UDPConn
	packets tun.Packets
	logger  *logrus.Logger
}

func (c *Client) handleOutgoing(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	logger := c.logger.WithField("worker", "outgoing").Dup().Logger

	for {
		select {
		case <-ctx.Done():
			logger.Trace("Closing due to parent context closure")
			return
		case packet := <-c.packets:
			p, err := packet.Get()
			if nil != err {
				logger.WithError(err).Error("Error reading from TUN device")
				return
			}

			if ok, err := filterOutgoingPacket(logger, p); nil != err {
				logger.WithError(err).Error("Failed to parse packet for filtering")
			} else if !ok {
				logger.Trace("Dropping packet")
			}

			n, err := c.conn.Write(p)
			if nil != err {
				logger.WithError(err).Error("Error sending data to server")
				return
			}
			logger.WithField("bytes", n).Trace("Outgoing packet has been written to tunnel connection")
		}
	}
}

func (c *Client) handleIncoming(wg *sync.WaitGroup) {
	defer wg.Done()
	logger := c.logger.WithField("worker", "incoming").Dup().Logger

	const bufferSize = 2048
	buffer := make([]byte, bufferSize)
	for {
		n, _, err := c.conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				logger.Trace("Ending server tunnel worker due to connection closure")
			} else {
				logger.WithError(err).Error("Error receiving data from server tunnel")
			}
			return
		}
		logger.WithField("bytes", n).Trace("Received bytes from server tunnel")

		n, err = c.t.Write(buffer[:n])
		if nil != err {
			logger.WithError(err).Error("Error writing to TUN device")
			return
		}
		logger.WithField("bytes", n).Trace("Incoming packet has been written to TUN device")
	}
}

func determineVersion(packet []byte) (int, error) {
	if len(packet) < 1 {
		return 0, os.ErrInvalid
	}

	return int(packet[0] >> 4), nil
}

func filterOutgoingPacket(logger *logrus.Logger, p tun.Packet) (bool, error) {
	v, err := determineVersion(p)
	if nil != err {
		return false, err
	}

	var decoder gopacket.Decoder
	switch v {
	case 6:
		logger.Trace("Skipping IPv6 packet")
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
		logger.
			WithFields(logrus.Fields{
				"seq":         icmp.Seq,
				"id":          icmp.Id,
				"payload_len": len(icmp.Payload),
			}).
			Trace("Detected ICMPv4 packet")
		return true, nil
	}

	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		logger.
			WithFields(logrus.Fields{
				"src": ip.SrcIP.String(),
				"dst": ip.DstIP.String(),
			}).
			Trace("Detected IPv4 packet")

		if layer := packet.TransportLayer(); nil != layer {
			if layer, ok := layer.(*layers.UDP); ok {
				logger.
					WithFields(logrus.Fields{
						"src_port": layer.SrcPort.String(),
						"dst_port": layer.DstPort.String(),
					}).
					Trace("Detected UDP packet")
				if layer.DstPort == 5353 && layer.SrcPort == 5353 && ip.DstIP.String() == "224.0.0.251" { // mDNS
					logger.Trace("Skipping mDNS packet")
					return false, nil
				}
				return true, nil
			}
		}
	}

	return false, nil
}
