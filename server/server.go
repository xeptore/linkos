package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"go.uber.org/zap"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/iputil"
	"github.com/xeptore/linkos/retry"
)

type (
	Server struct {
		gnet.BuiltinEventEngine
		engine      gnet.Engine
		cfg         *config.Server
		broadcastIP net.IP
		gatewayIP   net.IP
		subnetIPNet *net.IPNet
		tick        time.Duration
		clientConns []*ClientConnection
		hostConns   []*ClientConnection
		hostIP      net.IP
		logger      zerolog.Logger
	}
	ClientConnection struct {
		Conn          io.WriteCloser
		RemoteAddr    string
		LastKeepAlive int64
		IsIdle        bool
	}
)

func New(logger zerolog.Logger, cfg *config.Server) (*Server, error) {
	ip, subnetIPNet, err := net.ParseCIDR(cfg.IPNet)
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

	clientConns := make([]*ClientConnection, config.DefaultServerMaxClients)
	for i := range clientConns {
		clientConns[i] = &ClientConnection{
			Conn:          discard,
			RemoteAddr:    "",
			LastKeepAlive: time.Now().Unix(),
			IsIdle:        true,
		}
	}

	hostConns := make([]*ClientConnection, config.DefaultServerMaxClients)
	for i := range hostConns {
		hostConns[i] = &ClientConnection{
			Conn:          discard,
			RemoteAddr:    "",
			LastKeepAlive: time.Now().Unix(),
			IsIdle:        true,
		}
	}

	server := &Server{
		BuiltinEventEngine: gnet.BuiltinEventEngine{},
		engine:             gnet.Engine{},
		cfg:                cfg,
		broadcastIP:        broadcastIP,
		gatewayIP:          gatewayIP,
		subnetIPNet:        subnetIPNet,
		tick:               config.DefaultServerCleanupTickIntervalSec * time.Second,
		clientConns:        clientConns,
		hostConns:          hostConns,
		hostIP:             net.ParseIP(cfg.HostIP).To4(),
		logger:             logger,
	}
	return server, nil
}

func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

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
		for clientIdx, clientConn := range s.clientConns {
			if err := clientConn.Conn.Close(); nil != err {
				s.logger.Error().Func(errutil.TreeLog(err)).Err(err).Int("client_idx", clientIdx).Msg("Failed to close client connection")
			}
		}
		s.logger.Debug().Msg("Server engine stopped")
	}()

	opts := []gnet.Option{
		gnet.WithLoadBalancing(gnet.RoundRobin),
		gnet.WithReuseAddr(false),
		gnet.WithReusePort(false),
		gnet.WithBindToDevice(s.cfg.BindDev),
		gnet.WithReadBufferCap(s.cfg.BufferSize),
		gnet.WithWriteBufferCap(s.cfg.BufferSize),
		gnet.WithLockOSThread(false),
		gnet.WithTicker(true),
		gnet.WithSocketRecvBuffer(s.cfg.SocketSendBuffer),
		gnet.WithSocketSendBuffer(s.cfg.SocketRecvBuffer),
		gnet.WithLogLevel(logging.PanicLevel),
		gnet.WithLogger(logging.Logger(zap.NewNop().Sugar())),
	}

	switch {
	case s.cfg.NumEventLoops < 0:
		opts = append(opts, gnet.WithMulticore(false))
	case s.cfg.NumEventLoops == 0:
		opts = append(opts, gnet.WithNumEventLoop(runtime.NumCPU()))
	default:
		opts = append(opts, gnet.WithNumEventLoop(s.cfg.NumEventLoops))
	}

	clientPorts := make([]uint16, config.DefaultServerMaxClients)
	for i := range config.DefaultServerMaxClients {
		clientPorts[i] = config.ClientBasePort + i
	}
	protoAddrs := lo.Map(
		slices.Concat(config.DefaultHostPorts, clientPorts),
		func(port uint16, _ int) string {
			return "udp4://" + net.JoinHostPort(s.cfg.BindHost, strconv.Itoa(int(port)))
		},
	)
	s.logger.Debug().Strs("proto_addrs", protoAddrs).Msg("Starting engine")
	if err := gnet.Rotate(s, protoAddrs, opts...); nil != err {
		if errors.Is(err, ctx.Err()) {
			s.logger.Debug().Msg("Server engine stopped due to context error")
			return err
		}
		s.logger.Error().Func(errutil.TreeLog(err)).Err(err).Msg("Server engine stopped due to unknown error")
	}

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

	for clientIdx, clientConn := range s.clientConns {
		if now-clientConn.LastKeepAlive > config.DefaultKeepAliveSec*config.DefaultInactivityKeepAliveLimit && !clientConn.IsIdle {
			clientConn.IsIdle = true
			logger := s.logger.With().Int("client_idx", clientIdx).Logger()
			logger.Warn().Msg("Marked client as disconnected due to passing missed keep-alive threshold")
			if err := clientConn.Conn.Close(); nil != err {
				logger.Error().Func(errutil.TreeLog(err)).Err(err).Msg("Failed to close stale client connection")
			} else {
				logger.Debug().Msg("Closed stale client connection")
			}
		}
	}

	for portIdx, conn := range s.hostConns {
		if now-conn.LastKeepAlive > config.DefaultKeepAliveSec*config.DefaultInactivityKeepAliveLimit && !conn.IsIdle {
			conn.IsIdle = true
			logger := s.logger.With().Int("port_idx", portIdx).Logger()
			logger.Warn().Msg("Marked client as disconnected due to passing missed keep-alive threshold")
			if err := conn.Conn.Close(); nil != err {
				logger.Error().Func(errutil.TreeLog(err)).Err(err).Msg("Failed to close stale client connection")
			} else {
				logger.Debug().Msg("Closed stale client connection")
			}
		}
	}

	return s.tick, gnet.None
}

func (s *Server) OnTraffic(conn gnet.Conn) gnet.Action {
	packet, err := conn.Next(-1)
	if nil != err {
		s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to read packet")
		return gnet.Close
	}

	localAddr := conn.LocalAddr().String()
	localAddrPort, err := netip.ParseAddrPort(localAddr)
	if nil != err {
		s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to parse local address")
		return gnet.Close
	}
	localPort := localAddrPort.Port()
	logger := s.logger.
		With().
		Str("remote_addr", conn.RemoteAddr().String()).
		Str("local_addr", localAddr).
		Uint16("local_port", localPort).
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

	logger = logger.With().Str("src_ip", srcIP.String()).Str("dst_ip", dstIP.String()).Logger()
	logger.Debug().Msg("Received packet")

	clientIdx := clientIdxFromIP(srcIP)
	if clientIdx < 0 || clientIdx >= len(s.clientConns) {
		s.logger.Debug().Int("client_idx", clientIdx).Msg("Ignoring packet with out of range client index")
		return gnet.None
	}

	now := time.Now().Unix()

	switch {
	case dstIP.Equal(s.gatewayIP):
		// Only keep-alive packets should update the last keep-alive timestamp
		if srcIP.Equal(s.hostIP) {
			localPortIdx := slices.Index(config.DefaultHostPorts, localPort)
			if remoteAddr := conn.RemoteAddr().String(); s.hostConns[localPortIdx].RemoteAddr != remoteAddr || s.hostConns[localPortIdx].IsIdle {
				s.hostConns[localPortIdx] = &ClientConnection{
					Conn:          conn,
					RemoteAddr:    remoteAddr,
					LastKeepAlive: now,
					IsIdle:        false,
				}
			} else {
				s.hostConns[localPortIdx].LastKeepAlive = now
			}
		} else {
			if remoteAddr := conn.RemoteAddr().String(); s.clientConns[clientIdx].RemoteAddr != remoteAddr || s.clientConns[clientIdx].IsIdle {
				s.clientConns[clientIdx] = &ClientConnection{
					Conn:          conn,
					RemoteAddr:    remoteAddr,
					LastKeepAlive: now,
					IsIdle:        false,
				}
			} else {
				s.clientConns[clientIdx].LastKeepAlive = now
			}
		}
	case dstIP.Equal(s.hostIP):
		err := retry.Do(func(attempt int) retry.Action {
			if written, err := s.hostConns[clientHostConnIndex(srcIP)].Conn.Write(packet); nil != err {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					if attempt > 3 {
						return retry.Fail(fmt.Errorf("server: failed to write packet as buffer is temporarily unavailable after %d attempts", attempt))
					}
					time.Sleep(time.Duration(attempt) * 17 * time.Millisecond)
					return retry.Retry()
				}
				return retry.Fail(err)
			} else if written != len(packet) {
				return retry.Fail(fmt.Errorf("server: expected to write entire %d bytes of packet, written: %d", len(packet), written))
			}
			return retry.Success()
		})
		if nil != err {
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
		} else {
			logger.Debug().Msg("Forwarded broadcast packet to destined client")
		}
	case dstIP.Equal(s.broadcastIP):
		if !srcIP.Equal(s.hostIP) {
			// Packet sent by a client should also be forwarded to the host over sender client's specific connection
			err := retry.Do(func(attempt int) retry.Action {
				if written, err := s.hostConns[clientHostConnIndex(srcIP)].Conn.Write(packet); nil != err {
					if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
						if attempt > 3 {
							return retry.Fail(fmt.Errorf("server: failed to write packet as buffer is temporarily unavailable after %d attempts", attempt))
						}
						time.Sleep(time.Duration(attempt) * 17 * time.Millisecond)
						return retry.Retry()
					}
					return retry.Fail(err)
				} else if written != len(packet) {
					return retry.Fail(fmt.Errorf("server: expected to write entire %d bytes of packet, written: %d", len(packet), written))
				}
				return retry.Success()
			})
			if nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
			} else {
				logger.Debug().Msg("Forwarded broadcast packet to destined client")
			}
		}

		for dstClientIdx, dstConn := range s.clientConns {
			if clientIdx == dstClientIdx {
				continue
			}
			logger = logger.With().Int("dst_client_idx", dstClientIdx).Logger()
			logger.Debug().Msg("Forwarding broadcast packet to client")
			err := retry.Do(func(attempt int) retry.Action {
				if written, err := dstConn.Conn.Write(packet); nil != err {
					if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
						if attempt > 3 {
							return retry.Fail(fmt.Errorf("server: failed to write packet as buffer is temporarily unavailable after %d attempts", attempt))
						}
						time.Sleep(time.Duration(attempt) * 17 * time.Millisecond)
						return retry.Retry()
					}
					return retry.Fail(err)
				} else if written != len(packet) {
					return retry.Fail(fmt.Errorf("server: expected to write entire %d bytes of packet, written: %d", len(packet), written))
				}
				return retry.Success()
			})
			if nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
			} else {
				logger.Debug().Msg("Forwarded broadcast packet to destined client")
			}
		}
	default:
		// Client-to-client packet
		dstClientIdx := clientIdxFromIP(dstIP)
		if dstClientIdx >= len(s.clientConns) {
			logger.Debug().Int("dst_client_idx", dstClientIdx).Msg("Ignoring packet with out of range destination client index")
			return gnet.None
		}
		dstConn := s.clientConns[dstClientIdx]
		logger.Debug().Msg("Forwarding broadcast packet to client")
		err := retry.Do(func(attempt int) retry.Action {
			if written, err := dstConn.Conn.Write(packet); nil != err {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					if attempt > 3 {
						return retry.Fail(fmt.Errorf("server: failed to write packet as buffer is temporarily unavailable after %d attempts", attempt))
					}
					time.Sleep(time.Duration(attempt) * 17 * time.Millisecond)
					return retry.Retry()
				}
				return retry.Fail(err)
			} else if written != len(packet) {
				return retry.Fail(fmt.Errorf("server: expected to write entire %d bytes of packet, written: %d", len(packet), written))
			}
			return retry.Success()
		})
		if nil != err {
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
		} else {
			logger.Debug().Msg("Forwarded broadcast packet to destined client")
		}
	}
	return gnet.None
}

func clientIdxFromIP(ip net.IP) int {
	return int(ip[3] - 2)
}

func clientHostConnIndex(ip net.IP) int {
	return int(ip[3] - 2)
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
	return srcIP.To4(), destIP.To4(), nil
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
