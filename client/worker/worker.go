//go:build windows && amd64

package worker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	"github.com/xeptore/linkos/pool"
	"github.com/xeptore/linkos/tun"
)

type common struct {
	session         *tun.Session
	serverHost      string
	serverPort      uint16
	writeBufferSize int
	readBufferSize  int
	srcIP           net.IP
	logger          zerolog.Logger
}

type Send struct{ common }

type Recv struct{ common }

func NewSend(logger zerolog.Logger, bufferSize int, srcIP net.IP, serverHost string, serverPort uint16, session *tun.Session) *Send {
	return &Send{
		common: common{
			session:         session,
			serverHost:      serverHost,
			serverPort:      serverPort,
			writeBufferSize: bufferSize,
			readBufferSize:  0, // Nothing is expected to be received on this socket
			srcIP:           srcIP,
			logger:          logger,
		},
	}
}

func NewRecv(logger zerolog.Logger, bufferSize int, srcIP net.IP, serverHost string, serverPort uint16, session *tun.Session) *Recv {
	return &Recv{
		common: common{
			session:         session,
			serverHost:      serverHost,
			serverPort:      serverPort,
			writeBufferSize: 128, // For the keep-alive packet
			readBufferSize:  bufferSize,
			srcIP:           srcIP,
			logger:          logger,
		},
	}
}

func (w *Send) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	reader := w.session.Reader(ctx)
	defer func() {
		if err := reader.Close(); nil != err {
			if errors.Is(err, ctx.Err()) {
				return
			}
			w.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to close session packet reader")
		}
	}()

	var connectFailedAttempts int
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := w.connect(ctx)
			if nil != err {
				if errors.Is(err, ctx.Err()) {
					w.logger.Debug().Msg("Finishing client loop as connecting to server was cancelled")
					return
				}
				connectFailedAttempts++
				retryDelaySec := 2 * connectFailedAttempts
				w.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msgf("Failed to connect to server. Reconnecting in %d seconds", retryDelaySec)
				time.Sleep(time.Duration(retryDelaySec) * time.Second)
				continue
			} else {
				w.logger.Info().Msg("Connected to server")
				connectFailedAttempts = 0
			}

			if err := w.run(ctx, conn, reader); nil != err {
				// Pipe is broken due to issues with conn or context cancellation
				if errors.Is(err, ctx.Err()) {
					return
				}
				continue
			}
		}
	}
}

func (w *Send) run(ctx context.Context, conn *net.UDPConn, reader *tun.Reader) error {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	wg.Add(1)
	go func() { // Close connection on context cancellation
		defer wg.Done()
		<-ctx.Done()
		w.logger.Trace().Msg("Closing tunnel connection due to parent context closure")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				w.logger.Error().Err(err).Msg("Failed to close tunnel connection triggered by parent context closure")
			}
		} else {
			w.logger.Trace().Msg("Closed tunnel connection due to parent context closure")
		}
	}()

	wg.Add(1)
	go w.keepAlive(ctx, &wg, conn)

	wg.Add(1)
	go w.handleInbound(&wg, conn)

	return w.handleOutbound(conn, reader.Packets)
}

func (w *Send) handleOutbound(conn *net.UDPConn, packets <-chan *pool.Packet) error {
	for packet := range packets {
		if err := sendAndReleasePacket(w.logger, conn, packet); nil != err {
			return err
		}
	}
	return nil
}

func sendAndReleasePacket(logger zerolog.Logger, conn *net.UDPConn, p *pool.Packet) error {
	defer p.ReturnToPool()

	payload := p.Payload.Bytes()
	if ok, err := filterOutgoingPacket(logger, payload); nil != err {
		logger.Debug().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to filter packet")
		return nil
	} else if !ok {
		logger.Trace().Msg("Dropping filtered packet")
		return nil
	}

	packetSize := int64(p.Size)
	written, err := io.CopyN(conn, p.Payload, packetSize)
	switch {
	case nil != err:
		switch {
		case errors.Is(err, net.ErrClosed):
		case netutil.IsConnInterruptedError(err):
			logger.Error().Err(err).Msg("Failed to write packet to tunnel as connection already closed.")
		default:
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error sending data to server")
		}
		return err
	case written != packetSize:
		logger.Error().Int64("written", written).Int64("expected", packetSize).Msg("Failed to write all bytes of packet to tunnel connection")
	default:
		logger.Trace().Int64("bytes", written).Msg("Outgoing packet has been written to tunnel connection")
	}
	return nil
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
		Src:      w.srcIP,
		Dst:      gatewayIP,
	}

	// Marshal the header into a byte slice
	packet, err := header.Marshal()
	if nil != err {
		logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to marshal keep-alive packet header before checksum calculation")
		return
	}

	// Calculate the checksum (important for network transmission)
	header.Checksum = 0 // Reset checksum before recalculation
	header.Checksum = checksumIPv4(packet)

	// Marshal the header again with the calculated checksum
	packetBytes, err := header.Marshal()
	if nil != err {
		logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to marshal keep-alive packet header after checksum calculation")
		return
	}

	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Finishing keep-alive loop due to context cancellation")
			return
		case <-time.After(config.DefaultKeepAliveIntervalSec * time.Second):
			logger.Trace().Msg("Sending keep-alive packet")
			if written, err := conn.Write(packetBytes); nil != err {
				if netutil.IsConnInterruptedError(err) {
					logger.Error().Err(err).Msg("Failed to write packet keep-alive to tunnel as connection already closed.")
				} else {
					logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write keep-alive packet to connection")
				}
				return
			} else if written != len(packetBytes) {
				logger.Error().Int("written", written).Int("expected", len(packetBytes)).Msg("Failed to write all bytes of keep-alive packet to connection")
			} else {
				logger.Trace().Msg("Sent keep-alive packet")
			}
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

func (w *Send) handleInbound(wg *sync.WaitGroup, conn *net.UDPConn) {
	defer wg.Done()

	logger := w.logger.With().Str("worker", "incoming").Logger()
	for {
		if n, err := io.Copy(io.Discard, conn); nil != err {
			if !errors.Is(err, io.EOF) {
				logger.Error().Err(err).Msg("Failed to discard incoming packet")
			}
		} else {
			logger.Trace().Int64("bytes", n).Msg("Incoming packet has been discarded")
		}
		continue
	}
}

func (w *Recv) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	var connectFailedAttempts int
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := w.connect(ctx)
			if nil != err {
				if errors.Is(err, ctx.Err()) {
					w.logger.Debug().Msg("Finishing client loop as connecting to server was cancelled")
					return
				}
				connectFailedAttempts++
				retryDelaySec := 2 * connectFailedAttempts
				w.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msgf("Failed to connect to server. Reconnecting in %d seconds", retryDelaySec)
				time.Sleep(time.Duration(retryDelaySec) * time.Second)
				continue
			} else {
				w.logger.Info().Msg("Connected to server")
				connectFailedAttempts = 0
			}

			if err := w.run(ctx, conn); nil != err {
				// Pipe is broken due to issues with conn or context cancellation
				if errors.Is(err, ctx.Err()) {
					return
				}
				continue
			}
		}
	}
}

func (w *Recv) run(ctx context.Context, conn *net.UDPConn) error {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	wg.Add(1)
	go func() { // Close connection on context cancellation
		defer wg.Done()
		<-ctx.Done()
		w.logger.Trace().Msg("Closing tunnel connection due to parent context closure")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				w.logger.Error().Err(err).Msg("Failed to close tunnel connection triggered by parent context closure")
			}
		} else {
			w.logger.Trace().Msg("Closed tunnel connection due to parent context closure")
		}
	}()

	wg.Add(1)
	go w.keepAlive(ctx, &wg, conn)

	return w.handleInbound(conn)
}

func (w *Recv) handleInbound(conn *net.UDPConn) error {
	var (
		logger = w.logger.With().Str("worker", "incoming").Logger()
		buffer = make([]byte, w.readBufferSize)
	)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				logger.Trace().Msg("Ending server tunnel worker due to connection closure")
			} else {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error receiving data from server tunnel")
			}
			return err
		}
		logger.Trace().Int("bytes", n).Msg("Received bytes from server tunnel")

		written, err := w.session.Write(buffer[:n])
		switch {
		case nil != err:
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Error writing to TUN device")
			return err
		case written != n:
			logger.Error().Int("written", written).Int("expected", n).Msg("Failed to write all bytes to TUN device")
		default:
			logger.Trace().Int("bytes", n).Msg("Incoming packet has been written to TUN device")
		}
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
