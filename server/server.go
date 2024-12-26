package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/iputil"
)

type (
	Server struct {
		gnet.BuiltinEventEngine
		engine      gnet.Engine
		bindHost    string
		bindDev     string
		bufferSize  int
		broadcastIP net.IP
		gatewayIP   net.IP
		subnetIPNet *net.IPNet
		tick        time.Duration
		clients     []Client
		logger      zerolog.Logger
	}
	ClientPrivateIP  = string
	LocalConnAddr    = string
	Client           []*ClientConnection
	ClientConnection struct {
		Conn          io.WriteCloser
		ConnFd        int
		LastKeepAlive int64
		IsIdle        bool
	}
)

func New(logger zerolog.Logger, ipNet, bindHost, bindDev string, bufferSize int) (*Server, error) {
	ip, subnetIPNet, err := net.ParseCIDR(ipNet)
	if nil != err {
		return nil, fmt.Errorf("server: error parsing subnet CIDR: %v", err)
	}

	gatewayIP, err := iputil.GatewayIP(ip, 24)
	if nil != err {
		return nil, fmt.Errorf("server: failed to calculate gateway IP address: %v", err)
	}

	broadcastIP, err := getBroadcastIP(subnetIPNet)
	if nil != err {
		return nil, fmt.Errorf("server: failed to get broadcast IP: %v", err)
	}

	clients := make([]Client, config.DefaultServerMaxClients)
	for i := range clients {
		client := make([]*ClientConnection, len(config.DefaultClientRecvPorts))
		clients[i] = client
	}

	server := &Server{
		BuiltinEventEngine: gnet.BuiltinEventEngine{},
		engine:             gnet.Engine{},
		bindHost:           bindHost,
		bindDev:            bindDev,
		bufferSize:         bufferSize,
		broadcastIP:        broadcastIP,
		gatewayIP:          gatewayIP,
		subnetIPNet:        subnetIPNet,
		tick:               config.DefaultServerCleanupIntervalSec * time.Second,
		clients:            clients,
		logger:             logger,
	}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		s.logger.Debug().Msg("Stopping server engine due to parent context cancellation")
		if err := s.engine.Stop(ctx); nil != err {
			if !errors.Is(err, ctx.Err()) {
				s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to stop server engine")
			}
		}
		for clientIdx, clientConn := range s.clients {
			for portIdx, conn := range clientConn {
				if err := conn.Conn.Close(); nil != err {
					s.logger.Error().Err(err).Int("port_idx", portIdx).Int("client_idx", clientIdx).Msg("Failed to close client connection")
				}
			}
		}
		s.logger.Debug().Msg("Server engine stopped")
	}()

	opts := []gnet.Option{
		gnet.WithMulticore(true),
		gnet.WithNumEventLoop(len(config.DefaultClientRecvPorts) + len(config.DefaultClientSendPorts)),
		gnet.WithLoadBalancing(gnet.RoundRobin),
		gnet.WithReuseAddr(false),
		gnet.WithReusePort(false),
		gnet.WithBindToDevice(s.bindDev),
		gnet.WithReadBufferCap(s.bufferSize),
		gnet.WithWriteBufferCap(s.bufferSize),
		gnet.WithLockOSThread(false),
		gnet.WithTicker(true),
		gnet.WithSocketRecvBuffer(config.DefaultMaxKernelRecvBufferSize),
		gnet.WithSocketSendBuffer(config.DefaultMaxKernelSendBufferSize),
		gnet.WithLogger(logging.Logger(zap.NewNop().Sugar())),
	}
	protoAddrs := lo.Map(
		slices.Concat(config.DefaultClientRecvPorts, config.DefaultClientSendPorts),
		func(port string, _ int) string {
			return "udp4://" + net.JoinHostPort(s.bindHost, port)
		},
	)
	s.logger.Debug().Strs("proto_addrs", protoAddrs).Msg("Starting engine")
	if err := gnet.Rotate(s, protoAddrs, opts...); nil != err {
		if errors.Is(err, ctx.Err()) {
			s.logger.Debug().Msg("Server engine stopped due to context error")
			return err
		}
		s.logger.Error().Err(err).Msg("Server engine stopped due to unknown error")
	}

	cancel()
	wg.Wait()
	return nil
}

func (s *Server) isInSubnet(ip net.IP) bool {
	return s.subnetIPNet.Contains(ip)
}

func (s *Server) OnBoot(eng gnet.Engine) gnet.Action {
	s.logger.Info().Msg("Server started")
	s.engine = eng
	return gnet.None
}

func (s *Server) OnTick() (time.Duration, gnet.Action) {
	now := time.Now().Unix()
	for clientIdx, clientConn := range s.clients {
		for portIdx, conn := range clientConn {
			if now-conn.LastKeepAlive > config.DefaultKeepAliveIntervalSec*config.DefaultMissedKeepAliveThreshold {
				conn.IsIdle = true
				logger := s.logger.With().Int("client_idx", clientIdx).Int("port_idx", portIdx).Logger()
				logger.Debug().Msg("Marked client as disconnected due to passing missed keep-alive threshold")
				if err := conn.Conn.Close(); nil != err {
					logger.Error().Err(err).Msg("Failed to close stale client connection")
				} else {
					logger.Debug().Msg("Closed stale client connection")
				}
			}
		}
	}
	// for clientIdx := 0; clientIdx < len(s.clients); clientIdx++ {
	// 	for portIdx := 0; portIdx < len(config.DefaultClientRecvPorts); portIdx++ {
	// 		conn := s.clients[clientIdx][portIdx]
	// 		if now-conn.LastKeepAlive > config.DefaultKeepAliveIntervalSec*config.DefaultMissedKeepAliveThreshold {
	// 			conn.IsIdle = true
	// 			logger := s.logger.With().Int("client_idx", clientIdx).Int("port_idx", portIdx).Logger()
	// 			logger.Debug().Msg("Marked client as disconnected due to passing missed keep-alive threshold")
	// 			if err := conn.Conn.Close(); nil != err {
	// 				logger.Error().Err(err).Msg("Failed to close stale client connection")
	// 			} else {
	// 				logger.Debug().Msg("Closed stale client connection")
	// 			}
	// 		}
	// 	}
	// }
	return s.tick, gnet.None
}

func clientIdxFromIP(ip net.IP) int { // TODO: test this function
	return int(ip[3])
}

func (s *Server) OnTraffic(conn gnet.Conn) gnet.Action {
	recvBufferSize, err := unix.GetsockoptInt(conn.Fd(), unix.SOL_SOCKET, unix.SO_RCVBUF)
	fmt.Printf("\n\n\n\nRecv buffer size: %d\n\n\n\n", recvBufferSize)
	if err := os.NewSyscallError("getsockopt", err); nil != err {
		s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to get socket receive buffer size")
		return gnet.Close
	}
	return gnet.None

	packet, err := conn.Next(-1)
	if nil != err {
		s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to read packet")
		return gnet.Close
	}

	var (
		remoteAddr = conn.RemoteAddr().String()
		localAddr  = conn.LocalAddr().String()
	)
	localAddrPort, err := netip.ParseAddrPort(localAddr)
	if nil != err {
		s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to parse local address")
		return gnet.Close
	}
	localPort := strconv.Itoa(int(localAddrPort.Port()))
	logger := s.logger.
		With().
		Str("remote_addr", remoteAddr).
		Str("local_addr", localAddr).
		Str("local_port", localPort).
		Logger()

	if n := conn.InboundBuffered(); n > 0 {
		s.logger.Warn().Int("bytes", n).Int("read_bytes", len(packet)).Msg("More packets in buffer")
	}

	if l := len(packet); l < 20 {
		s.logger.Debug().Int("bytes", l).Msg("Ignoring invalid IP packet")
		return gnet.None
	} else {
		logger = logger.With().Int("bytes", l).Logger()
	}

	srcIP, dstIP, err := parseIPv4Header(packet)
	if nil != err {
		s.logger.Debug().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to parse packet IP header")
		return gnet.None
	} else if !s.isInSubnet(srcIP) || !s.isInSubnet(dstIP) {
		logger.Debug().Msg("Ignoring packet outside of subnet")
		return gnet.None
	}

	prvIP := srcIP.String()
	logger = logger.With().Str("src_ip", prvIP).Str("dst_ip", dstIP.String()).Logger()
	logger.Debug().Msg("Received packet")

	clientIdx := clientIdxFromIP(srcIP)
	if clientIdx < 0 || clientIdx >= len(s.clients) {
		s.logger.Debug().Int("client_idx", clientIdx).Msg("Ignoring packet with out of range client index")
		return gnet.None
	}

	if idx := clientSendPortIdx(localAddr); idx != -1 {
		// clientConn := client[idx]
		// if connFd := conn.Fd(); clientConn.ConnFd != connFd {
		// 	if err := conn.SetReadBuffer(s.bufferSize); nil != err {
		// 		logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set read buffer")
		// 	} else {
		// 		logger.Debug().Msg("Set connection read buffer size")
		// 	}
		// 	if err := conn.SetWriteBuffer(s.bufferSize); nil != err {
		// 		logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set write buffer")
		// 	} else {
		// 		logger.Debug().Msg("Set connection write buffer size")
		// 	}
		// 	clientConn.Conn = conn
		// 	clientConn.ConnFd = connFd
		// }

		switch {
		case dstIP.Equal(s.gatewayIP):
			logger.Debug().Msg("Handled client keep-alive packet")
			return gnet.None
		case dstIP.Equal(s.broadcastIP):
			logger.Debug().Msg("Broadcasting packet")
			for dstClientIdx, dstClientConn := range s.clients {
				if clientIdx == dstClientIdx {
					continue
				}
				logger = logger.With().Int("dst_client_idx", dstClientIdx).Logger()
				for dstLocalPort, dstConn := range dstClientConn {
					if dstConn.IsIdle {
						logger.Debug().Int("dst_local_port", dstLocalPort).Msg("Skipping idle client connection")
						continue
					}
					logger = logger.With().Int("dst_local_port", dstLocalPort).Logger()
					logger.Debug().Msg("Forwarding broadcast packet to client")
					if written, err := dstConn.Conn.Write(packet); nil != err {
						logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
					} else if written != len(packet) {
						logger.Error().Int("written", written).Msg("Failed to write entire packet")
					} else {
						logger.Debug().Msg("Broadcasted packet to client")
					}
					break
				}
			}
			return gnet.None
		default:
			logger.Debug().Msg("Forwarding packet")
			dstClientIdx := clientIdxFromIP(dstIP)
			if dstClientIdx > len(s.clients) {
				logger.Debug().Int("dst_client_idx", dstClientIdx).Msg("Ignoring packet with out of range destination client index")
				return gnet.None
			}
			clientConn := s.clients[dstClientIdx]
			for dstLocalPort, dstConn := range clientConn {
				if dstConn.IsIdle {
					logger.Debug().Int("dst_local_port", dstLocalPort).Msg("Skipping idle client connection")
					continue
				}
				logger = logger.With().Int("dst_local_port", dstLocalPort).Logger()
				logger.Debug().Msg("Forwarding packet to client")
				if written, err := dstConn.Conn.Write(packet); nil != err {
					logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
				} else if written != len(packet) {
					logger.Error().Int("written", written).Msg("Failed to write entire packet")
				} else {
					logger.Debug().Msg("Forwarding packet to client")
				}
				break
			}
			return gnet.None
		}
	} else if idx := clientRecvPortIdx(localAddr); idx != -1 {
		clientConn := s.clients[clientIdx][idx]
		if connFd := conn.Fd(); clientConn.ConnFd != connFd || clientConn.IsIdle {
			if err := conn.SetReadBuffer(s.bufferSize); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set read buffer")
			} else {
				logger.Debug().Msg("Set connection read buffer size")
			}
			if err := conn.SetWriteBuffer(s.bufferSize); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set write buffer")
			} else {
				logger.Debug().Msg("Set connection write buffer size")
			}
			clientConn = &ClientConnection{
				Conn:   conn,
				ConnFd: connFd,
				IsIdle: false,
			}
			s.clients[clientIdx][idx] = clientConn
		}
		clientConn.LastKeepAlive = time.Now().Unix()
		return gnet.None
	} else {
		logger.Debug().Msg("Ignoring packet with invalid port")
		return gnet.Close
	}
}

// TODO: check out of range array accesses
// TODO: check nil pointer dereferences
// TODO: check gnet sets default buffer size for connections

func clientSendPortIdx(p string) int {
	for i, port := range config.DefaultClientSendPorts {
		if p == port {
			return i
		}
	}
	return -1
}

func clientRecvPortIdx(p string) int {
	for i, port := range config.DefaultClientRecvPorts {
		if p == port {
			return i
		}
	}
	return -1
}

func parseIPv4Header(packet []byte) (srcIP, destIP net.IP, err error) {
	// IP version & IHL are in the first byte
	// Check version == 4
	versionIHL := packet[0]
	if version := versionIHL >> 4; version != 4 {
		return nil, nil, fmt.Errorf("ip: invalid packet version: %d", version)
	}

	srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15])
	destIP = net.IPv4(packet[16], packet[17], packet[18], packet[19])
	return srcIP, destIP, nil
}

func getBroadcastIP(subnet *net.IPNet) (net.IP, error) {
	ip := subnet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("server: invalid IPv4 address: %v", subnet.IP)
	}

	mask := subnet.Mask
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast, nil
}
