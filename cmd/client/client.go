//go:build windows && amd64

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/dnsutil"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/iputil"
	"github.com/xeptore/linkos/netutil"
	"github.com/xeptore/linkos/packet"
	"github.com/xeptore/linkos/pool"
)

type Client struct {
	t               *tun.Tun
	packets         tun.Packets
	serverAddr      string
	ip              net.IP
	incomingThreads int
	bufferSize      int
	logger          zerolog.Logger
}

func (c *Client) runLoop(ctx context.Context) error {
	connectFailedAttempts := 0
	for {
		conn, err := c.connect(ctx)
		if nil != err {
			if ctxErr := ctx.Err(); nil != ctxErr {
				c.logger.Debug().Msg("Finishing client loop as connecting to server was cancelled")
				return ctxErr
			}
			connectFailedAttempts++
			retryDelaySec := 2 * connectFailedAttempts
			c.logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msgf("Failed to connect to server. Reconnecting in %d seconds", retryDelaySec)
			time.Sleep(time.Duration(retryDelaySec) * time.Second)
			continue
		} else {
			c.logger.Info().Msg("Connected to server")
			connectFailedAttempts = 0
		}

		var wg sync.WaitGroup

		connCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-connCtx.Done()
			c.logger.Trace().Msg("Closing tunnel connection due to parent context closure")
			if err := conn.Close(); nil != err {
				if !errors.Is(err, net.ErrClosed) {
					c.logger.Error().Err(err).Msg("Failed to close tunnel connection triggered by parent context closure")
				}
			} else {
				c.logger.Trace().Msg("Closed tunnel connection due to parent context closure")
			}
		}()

		wg.Add(c.incomingThreads)
		for range c.incomingThreads {
			go c.handleInbound(&wg, conn)
		}

		wg.Add(1)
		go c.keepAlive(connCtx, &wg, conn)

		c.handleOutbound(ctx, conn)
		cancel()
		c.logger.Debug().Msg("Outbound worker returned. Closing tunnel connection")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				c.logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to close tunnel connection")
			}
		} else {
			c.logger.Debug().Msg("Closed tunnel connection")
		}

		c.logger.Trace().Msg("Waiting for inbound worker and tunnel connection close routine to return")
		wg.Wait()
		c.logger.Trace().Msg("Inbound worker and tunnel connection close routine returned")

		if err := ctx.Err(); nil != err {
			return err
		}
	}
}

func (c *Client) connect(ctx context.Context) (*net.UDPConn, error) {
	c.logger.Trace().Str("address", c.serverAddr).Msg("Resolving server address")

	serverHostname, serverPort, err := net.SplitHostPort(c.serverAddr)
	if nil != err {
		return nil, fmt.Errorf("client: invalid server address: %v", err)
	}

	var serverIP net.IP
	for {
		ip, err := dnsutil.ResolveAddr(ctx, c.logger, serverHostname)
		if nil != err {
			if errors.Is(err, ctx.Err()) {
				c.logger.Debug().Msg("Ending connect server IP resolution due to context cancellation")
				return nil, ctx.Err()
			}
			c.logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to resolve server IP address. Retrying in 5 seconds")
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
			}
		} else {
			serverIP = ip
			break
		}
	}

	c.logger.Info().Str("server_ip", serverIP.String()).Msg("Resolving server UDP address using IP address")
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(serverIP.String(), serverPort))
	if nil != err {
		return nil, fmt.Errorf("tunnel: failed to resolve server address: %v", err)
	}
	c.logger.Trace().Msg("Resolved server address")

	c.logger.Trace().Msg("Dialing server")
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if nil != err {
		return nil, fmt.Errorf("tunnel: failed to connect to server: %v", err)
	}
	if err := conn.SetReadBuffer(c.bufferSize); nil != err {
		return nil, fmt.Errorf("tunnel: failed to set read buffer: %v", err)
	}
	if err := conn.SetWriteBuffer(c.bufferSize); nil != err {
		return nil, fmt.Errorf("tunnel: failed to set write buffer: %v", err)
	}

	return conn, nil
}

func (c *Client) handleOutbound(ctx context.Context, conn *net.UDPConn) {
	logger := c.logger.With().Str("worker", "outgoing").Logger()

	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Closing due to parent context closure")
			return
		case packet := <-c.packets:
			p, err := packet.Get()
			if nil != err {
				if errors.Is(err, ctx.Err()) {
					return
				}
				logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Error reading from TUN device")
				return
			}

			if err := sendAndReleasePacket(logger, conn, p); nil != err {
				return
			}
		}
	}
}

func sendAndReleasePacket(logger zerolog.Logger, conn *net.UDPConn, p *pool.Packet) error {
	defer p.ReturnToPool()

	payload := p.Payload.Bytes()
	if ok, err := filterOutgoingPacket(logger, payload); nil != err {
		logger.Debug().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to filter packet")
		return nil
	} else if !ok {
		logger.Trace().Msg("Dropping filtered packet")
		return nil
	}

	pa, err := packet.FromIP(payload)
	if nil != err {
		if errors.Is(err, errors.ErrUnsupported) {
			logger.Debug().Msg("Ignoring unsupported outgoing packet")
		} else {
			logger.Error().Err(err).Msg("Failed to parse outgoing IPv4 packet")
		}
		return nil
	}

	n, err := pa.Write(conn)
	if nil != err {
		switch {
		case errors.Is(err, net.ErrClosed):
		case netutil.IsConnClosedError(err):
			logger.Error().Err(err).Msg("Failed to write packet to tunnel as connection already closed.")
		default:
			logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Error sending data to server")
		}
		return err
	}
	logger.Trace().Int("bytes", n).Msg("Outgoing packet has been written to tunnel connection")
	return nil
}

func (c *Client) keepAlive(ctx context.Context, wg *sync.WaitGroup, conn *net.UDPConn) {
	defer wg.Done()
	logger := c.logger.With().Str("worker", "keep_alive").Logger()

	gatewayIP, err := iputil.GatewayIP(c.ip, 24)
	if nil != err {
		logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to calculate gatewat IP address from client IP address")
		return
	}
	logger = logger.With().Str("gateway_ip", gatewayIP.String()).Logger()

	pa := packet.Packet{
		Header: packet.Header{
			SrcIP: c.ip,
			DstIP: gatewayIP,
		},
		Raw: []byte{},
	}

	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Finishing keep-alive loop due to context cancellation")
			return
		case <-time.After(config.DefaultKeepAliveIntervalSec * time.Second):
			logger.Trace().Msg("Sending keep-alive packet")
			if _, err := pa.Write(conn); nil != err {
				if netutil.IsConnClosedError(err) {
					logger.Error().Err(err).Msg("Failed to write packet to tunnel as connection already closed.")
				} else {
					logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to write keep-alive packet to connection")
				}
				return
			}
			logger.Trace().Msg("Sent keep-alive packet")
		}
	}
}

func checksumIPv4(b []byte) int {
	sum := 0
	for i := 0; i < len(b)-1; i += 2 {
		sum += int(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 != 0 {
		sum += int(b[len(b)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^sum
}

func (c *Client) handleInbound(wg *sync.WaitGroup, conn *net.UDPConn) {
	defer wg.Done()
	logger := c.logger.With().Str("worker", "incoming").Logger()

	buffer := make([]byte, c.bufferSize)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				logger.Trace().Msg("Ending server tunnel worker due to connection closure")
			} else {
				logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Error receiving data from server tunnel")
			}
			return
		}
		logger.Trace().Int("bytes", n).Msg("Received bytes from server tunnel")

		raw, err := packet.Decompress(buffer[:n])
		if nil != err {
			logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to decompress incoming packet")
			continue
		}

		n, err = c.t.Write(raw)
		if nil != err {
			logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Error writing to TUN device")
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

func filterOutgoingPacket(logger zerolog.Logger, p []byte) (bool, error) {
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
