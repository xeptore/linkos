//go:build windows && amd64

package worker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"golang.org/x/net/ipv4"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/dnsutil"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/iputil"
	"github.com/xeptore/linkos/netutil"
)

type common struct {
	serverHost      string
	serverPort      uint16
	writeBufferSize int
	readBufferSize  int
	srcIP           net.IP
	logger          zerolog.Logger
}

func (w *common) keepAlive(ctx context.Context, wg *sync.WaitGroup, conn *net.UDPConn) {
	defer wg.Done()
	logger := w.logger.With().Str("worker", "keep_alive").Logger()

	gatewayIP, err := iputil.GatewayIP(w.srcIP, 24)
	if nil != err {
		logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to calculate gatewat IP address from client IP address")
		return
	}
	logger = logger.With().Str("gateway_ip", gatewayIP.String()).Logger()

	packetBytes, err := newKeepAlivePacket(w.srcIP, gatewayIP)
	if nil != err {
		logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to craft keep-alive packet")
		return
	}

	tick := time.Tick(config.DefaultKeepAliveIntervalSec * time.Second)
	initialTick := time.After(1 * time.Second)

	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Finishing keep-alive loop due to context cancellation")
			return
		case <-initialTick:
			if err := writeKeepAlivePacket(logger, packetBytes, conn); nil != err {
				return
			}
		case <-tick:
			if err := writeKeepAlivePacket(logger, packetBytes, conn); nil != err {
				return
			}
		}
	}
}

// credit goes to https://devv.ai
func newKeepAlivePacket(src, dst net.IP) ([]byte, error) {
	header := &ipv4.Header{ //nolint:exhaustruct
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TotalLen: ipv4.HeaderLen,
		ID:       0,
		Flags:    0,
		FragOff:  0,
		TTL:      64,
		Protocol: 0,
		Checksum: 0,
		Src:      src,
		Dst:      dst,
	}

	// Marshal the header into a byte slice
	packet, err := header.Marshal()
	if nil != err {
		return nil, fmt.Errorf("failed to marshal keep-alive packet header before checksum calculation: %v", err)
	}

	// Calculate the checksum (important for network transmission)
	header.Checksum = 0 // Reset checksum before recalculation
	header.Checksum = checksumIPv4(packet)

	// Marshal the header again with the calculated checksum
	packetBytes, err := header.Marshal()
	if nil != err {
		return nil, fmt.Errorf("failed to marshal keep-alive packet header after checksum calculation: %v", err)
	}
	return packetBytes, nil
}

func writeKeepAlivePacket(logger zerolog.Logger, p []byte, conn *net.UDPConn) error {
	logger.Trace().Msg("Sending keep-alive packet")
	if written, err := conn.Write(p); nil != err {
		if netutil.IsConnInterruptedError(err) {
			logger.Warn().Msg("Failed to write keep-alive packet to tunnel as connection was interrupted.")
		} else {
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write keep-alive packet to connection")
		}
		return err
	} else if written != len(p) {
		logger.Error().Int("written", written).Int("expected", len(p)).Msg("Failed to write all bytes of keep-alive packet to connection")
	} else {
		logger.Trace().Msg("Sent keep-alive packet")
	}
	return nil
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

func (w *common) connect(ctx context.Context) (*net.UDPConn, error) {
	w.logger.Trace().Str("server_host", w.serverHost).Msg("Resolving server address")

	var serverIP net.IP
	for {
		ip, err := dnsutil.ResolveAddr(ctx, w.logger, w.serverHost)
		if nil != err {
			if errors.Is(err, ctx.Err()) {
				w.logger.Debug().Msg("Ending connect server IP resolution due to context cancellation")
				return nil, ctx.Err()
			}
			w.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to resolve server IP address. Retrying in 5 seconds")
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

	w.logger.Info().Str("server_ip", serverIP.String()).Msg("Resolving server UDP address using IP address")
	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(serverIP.String(), strconv.Itoa(int(w.serverPort))))
	if nil != err {
		return nil, fmt.Errorf("worker: failed to resolve server address: %v", err)
	}
	w.logger.Trace().Msg("Resolved server address")

	w.logger.Trace().Msg("Dialing server")
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if nil != err {
		return nil, fmt.Errorf("worker: failed to connect to server: %v", err)
	}

	if err := conn.SetReadBuffer(w.readBufferSize); nil != err {
		return nil, fmt.Errorf("worker: failed to set read buffer: %v", err)
	}
	if err := conn.SetWriteBuffer(w.writeBufferSize); nil != err {
		return nil, fmt.Errorf("worker: failed to set write buffer: %v", err)
	}

	return conn, nil
}
