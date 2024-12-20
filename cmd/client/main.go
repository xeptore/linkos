//go:build windows && amd64

package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"golang.org/x/net/ipv4"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/dnsutil"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/iputil"
	"github.com/xeptore/linkos/log"
	"github.com/xeptore/linkos/netutil"
	"github.com/xeptore/linkos/pool"
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

func waitForEnter(ctx context.Context) {
	if cause := context.Cause(ctx); errors.Is(cause, errSigTrapped) {
		return
	}

	fmt.Fprint(os.Stdout, "Press enter to exit...")
	bufio.NewReader(io.LimitReader(os.Stdin, 1)).ReadBytes('\n') //nolint:errcheck
}

func main() {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	logger, err := log.New()
	if nil != err {
		fmt.Fprintf(os.Stderr, "Error: failed to create logger: %v\n", err)
		waitForEnter(ctx)
		return
	}
	logger = logger.With().Str("version", Version).Logger()
	logger.Info().Msg("Starting VPN client")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Context canceled before receiving a close signal")
		case <-c:
			logger.Warn().Msg("Close signal received. Exiting...")
			signal.Stop(c)
			cancel(errSigTrapped)
		}
	}()

	if err := run(ctx, logger); nil != err {
		if cause := context.Cause(ctx); errors.Is(cause, errSigTrapped) {
			logger.Debug().Msg("Client retutned due to receiving a signal")
		} else if createErr := new(tun.CreateError); errors.As(err, &createErr) {
			logger.Error().Err(createErr).Msg("Failed to create VPN tunnel. Try restarting your machine if the problem persists.")
		} else if openURLErr := new(OpenLatestVersionDownloadURLError); errors.As(err, &openURLErr) {
			logger.
				Error().
				Err(err).
				Dict("err_tree", errutil.Tree(err).LogDict()).
				Func(func(e *zerolog.Event) {
					if logger.GetLevel() < zerolog.InfoLevel {
						e.Str("combined_output", string(openURLErr.CommandOut))
					}
				}).
				Str("download_url", openURLErr.URL).
				Msg("Failed to open download URL. You can still download it manually using the URL.")
		} else {
			logger.Error().Err(err).Msg("Failed to run the application")
		}
	}

	cancel(nil)
	wg.Wait()
	waitForEnter(ctx)
}

type OpenLatestVersionDownloadURLError struct {
	URL        string
	CommandOut []byte
}

func (err *OpenLatestVersionDownloadURLError) Error() string {
	return "failed to open latest version download URL"
}

func run(ctx context.Context, logger zerolog.Logger) (err error) {
	cfg, err := config.LoadClient(configFileName)
	if nil != err {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(configFileName, config.ClientConfigTemplate, 0o0600); nil != err {
				return fmt.Errorf("config: file was not found. Tried creating a template file but did not succeeded: %v", err)
			}
			return fmt.Errorf("config: file was not found. A template is created with name %s. You should fill with proper values: %v", configFileName, err)
		}
		return fmt.Errorf("config: failed to load: %v", err)
	}
	logger = logger.Level(cfg.LogLevel)
	logger.Debug().Dict("config_options", cfg.LogDict()).Msg("Loaded configuration")

	if Version != "dev" {
		logger.Trace().Str("current_version", Version).Msg("Checking for new releases")
		if exists, latestTag, err := update.NewerVersionExists(ctx, logger, Version); nil != err {
			logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to check for newer version existence. Make sure you have internet access and rerun the application.")
			return nil
		} else if exists {
			logger.Error().Msg("Newer version exists. Download URL will be opened soon")
			time.Sleep(time.Second)
			downloadURL := "https://github.com/xeptore/linkos/releases/download/" + latestTag + "/client_" + runtime.GOOS + "_" + runtime.GOARCH + ".zip"
			cmd := []string{"start", downloadURL}
			if out, err := exec.Command("cmd.exe", "/c", strings.Join(cmd, " ")).CombinedOutput(); nil != err { //nolint:gosec
				return &OpenLatestVersionDownloadURLError{URL: downloadURL, CommandOut: out}
			}
			return nil
		}
		logger.Info().Msg("Already running the latest version")
	}

	packetPool := pool.New(cfg.BufferSize)

	logger.Trace().Msg("Initializing VPN tunnel")
	t, err := tun.New(logger.With().Str("module", "tun").Logger(), cfg.RingSize, packetPool)
	if nil != err {
		return fmt.Errorf("tun: failed to create: %w", err)
	}
	logger.Info().Msg("VPN tunnel initialized")

	logger.Trace().Msg("Assigning IP address to tunnel adapter")
	if err := t.AssignIPv4(cfg.IP); nil != err {
		return fmt.Errorf("tun: failed to assign IP address: %v", err)
	}
	logger.Info().Msg("Assigned IP address to tunnel adapter")

	logger.Debug().Msg("Setting adapter IPv4 options")
	if err := t.SetIPv4Options(cfg.MTU); nil != err {
		return fmt.Errorf("tun: failed to set adapter IPv4 options: %v", err)
	}
	logger.Debug().Msg("Set adapter IPv4 options")

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

	client := Client{
		t:               t,
		packets:         packets,
		serverAddr:      cfg.ServerAddr,
		ip:              net.ParseIP(cfg.IP),
		incomingThreads: cfg.IncomingThreads,
		bufferSize:      cfg.BufferSize,
		logger:          logger.With().Str("module", "client").Logger(),
	}

	logger.WithLevel(log.NoLevel).Msg("Starting VPN client")
	return client.runLoop(ctx)
}

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

func sendAndReleasePacket(logger zerolog.Logger, conn *net.UDPConn, packet *pool.Packet) error {
	defer packet.ReturnToPool()

	if ok, err := filterOutgoingPacket(logger, packet.Payload.Bytes()); nil != err {
		logger.Debug().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to filter packet")
		return nil
	} else if !ok {
		logger.Trace().Msg("Dropping filtered packet")
		return nil
	}

	n, err := io.CopyN(conn, packet.Payload, int64(packet.Size))
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
	logger.Trace().Int64("bytes", n).Msg("Outgoing packet has been written to tunnel connection")
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
		Src:      c.ip,
		Dst:      gatewayIP,
	}

	// Marshal the header into a byte slice
	packet, err := header.Marshal()
	if nil != err {
		logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to marshal keep-alive packet header before checksum calculation")
		return
	}

	// Calculate the checksum (important for network transmission)
	header.Checksum = 0 // Reset checksum before recalculation
	header.Checksum = checksumIPv4(packet)

	// Marshal the header again with the calculated checksum
	packetBytes, err := header.Marshal()
	if nil != err {
		logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to marshal keep-alive packet header after checksum calculation")
		return
	}

	for {
		select {
		case <-ctx.Done():
			logger.Trace().Msg("Finishing keep-alive loop due to context cancellation")
			return
		case <-time.After(config.DefaultKeepAliveIntervalSec * time.Second):
			logger.Trace().Msg("Sending keep-alive packet")
			if _, err := conn.Write(packetBytes); nil != err {
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

		n, err = c.t.Write(buffer[:n])
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
