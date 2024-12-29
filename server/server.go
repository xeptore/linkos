package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	"github.com/xeptore/linkos/mathutil"
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
		clients     []Client
		logger      zerolog.Logger
	}
	ClientPrivateIP  = string
	LocalConnAddr    = string
	Client           []*ClientConnection
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

	clients := make([]Client, config.DefaultServerMaxClients)
	for i := range clients {
		client := make([]*ClientConnection, len(config.DefaultClientRecvPorts))
		clients[i] = client
		for j := range len(config.DefaultClientRecvPorts) {
			clients[i][j] = &ClientConnection{
				Conn:          discard,
				RemoteAddr:    "",
				LastKeepAlive: time.Now().Unix(),
				IsIdle:        true,
			}
		}
	}

	server := &Server{
		BuiltinEventEngine: gnet.BuiltinEventEngine{},
		engine:             gnet.Engine{},
		cfg:                cfg,
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
		gnet.WithLoadBalancing(gnet.RoundRobin),
		gnet.WithReuseAddr(false),
		gnet.WithReusePort(false),
		gnet.WithBindToDevice(s.cfg.BindDev),
		gnet.WithReadBufferCap(s.cfg.BufferSize),
		gnet.WithWriteBufferCap(s.cfg.BufferSize),
		gnet.WithLockOSThread(false),
		gnet.WithTicker(true),
		gnet.WithSocketRecvBuffer(int(s.cfg.SendBuffer)),
		gnet.WithSocketSendBuffer(int(s.cfg.RecvBuffer)),
		gnet.WithLogLevel(logging.PanicLevel),
		gnet.WithLogger(logging.Logger(zap.NewNop().Sugar())),
	}

	if s.cfg.NumEventLoops > 0 {
		opts = append(
			opts,
			gnet.WithMulticore(true),
			gnet.WithNumEventLoop(s.cfg.NumEventLoops),
		)
	} else {
		opts = append(
			opts,
			gnet.WithMulticore(false),
		)
	}

	protoAddrs := lo.Map(
		slices.Concat(config.DefaultClientRecvPorts, config.DefaultClientSendPorts),
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
			if now-conn.LastKeepAlive > config.DefaultKeepAliveIntervalSec*config.DefaultMissedKeepAliveThreshold && !conn.IsIdle {
				conn.IsIdle = true
				logger := s.logger.With().Int("client_idx", clientIdx).Int("port_idx", portIdx).Logger()
				logger.Warn().Msg("Marked client as disconnected due to passing missed keep-alive threshold")
				if err := conn.Conn.Close(); nil != err {
					logger.Error().Err(err).Msg("Failed to close stale client connection")
				} else {
					logger.Debug().Msg("Closed stale client connection")
				}
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
	if clientIdx < 0 || clientIdx >= len(s.clients) {
		s.logger.Debug().Int("client_idx", clientIdx).Msg("Ignoring packet with out of range client index")
		return gnet.None
	}

	now := time.Now().Unix()

	if localPortIdx := slices.Index(config.DefaultClientSendPorts, localPort); localPortIdx != -1 {
		switch {
		case dstIP.Equal(s.gatewayIP):
			logger.Debug().Msg("Handled client keep-alive packet")
			return gnet.None
		case dstIP.Equal(s.broadcastIP):
			logger.Debug().Msg("Broadcasting packet")
			for dstClientIdx, dstClient := range s.clients {
				if clientIdx == dstClientIdx {
					continue
				}
				logger = logger.With().Int("dst_client_idx", dstClientIdx).Logger()
				sign := mathutil.RandomSign()
				for i := range len(config.DefaultClientRecvPorts) {
					dstPortIdx := (int(now) + dstClientIdx + localPortIdx + (i * sign)) % len(config.DefaultClientRecvPorts)
					dstConn := dstClient[dstPortIdx]
					if dstConn.IsIdle {
						logger.Debug().Int("dst_local_port", dstPortIdx).Msg("Skipping idle client connection")
						continue
					}
					logger = logger.With().Int("dst_local_port", dstPortIdx).Logger()
					logger.Debug().Msg("Forwarding broadcast packet to client")
					err := retry.Do(func(attempt int) (retry.Action, error) {
						if written, err := dstConn.Conn.Write(packet); nil != err {
							if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
								if attempt > 3 {
									return retry.Abort, fmt.Errorf("server: failed to write packet as buffer is temporarily unavailable after %d attempts", attempt)
								}
								return retry.Retry, errors.New("server: failed to write packet as buffer is temporarily unavailable")
							}
							return retry.Abort, err
						} else if written != len(packet) {
							return retry.Abort, fmt.Errorf("server: expected to write entire %d bytes of packet, written: %d", len(packet), written)
						}
						return retry.Abort, nil
					})
					if nil != err {
						logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
					} else {
						logger.Debug().Msg("Forwarded broadcast packet to client")
					}
					break
				}
			}
			return gnet.None
		default:
			logger.Debug().Msg("Forwarding packet")
			dstClientIdx := clientIdxFromIP(dstIP)
			if dstClientIdx >= len(s.clients) {
				logger.Debug().Int("dst_client_idx", dstClientIdx).Msg("Ignoring packet with out of range destination client index")
				return gnet.None
			}
			logger = logger.With().Int("dst_client_idx", dstClientIdx).Logger()
			dstClient := s.clients[dstClientIdx]
			sign := mathutil.RandomSign()
			for i := range len(config.DefaultClientRecvPorts) {
				dstLocalPortIdx := (int(now) + dstClientIdx + localPortIdx + (i * sign)) % len(config.DefaultClientRecvPorts)
				dstConn := dstClient[dstLocalPortIdx]
				if dstConn.IsIdle {
					logger.Debug().Int("dst_local_port_idx", dstLocalPortIdx).Msg("Skipping idle client connection")
					continue
				}
				logger = logger.With().Int("dst_local_port_idx", dstLocalPortIdx).Logger()
				logger.Debug().Msg("Forwarding packet to client")
				err := retry.Do(func(attempt int) (retry.Action, error) {
					if written, err := dstConn.Conn.Write(packet); nil != err {
						if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
							if attempt > 3 {
								return retry.Abort, fmt.Errorf("server: failed to write packet as buffer is temporarily unavailable after %d attempts", attempt)
							}
							return retry.Retry, errors.New("server: failed to write packet as buffer is temporarily unavailable")
						}
						return retry.Abort, err
					} else if written != len(packet) {
						return retry.Abort, fmt.Errorf("server: expected to write entire %d bytes of packet, written: %d", len(packet), written)
					}
					return retry.Abort, nil
				})
				if nil != err {
					logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
				} else {
					logger.Debug().Msg("Forwarded broadcast packet to client")
				}
				break
			}
			return gnet.None
		}
	} else if localPortIdx := slices.Index(config.DefaultClientRecvPorts, localPort); localPortIdx != -1 {
		if remoteAddr := conn.RemoteAddr().String(); s.clients[clientIdx][localPortIdx].RemoteAddr != remoteAddr || s.clients[clientIdx][localPortIdx].IsIdle {
			if err := conn.SetReadBuffer(s.cfg.BufferSize); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set read buffer")
			} else {
				logger.Debug().Msg("Set connection read buffer size")
			}
			if err := conn.SetWriteBuffer(s.cfg.BufferSize); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set write buffer")
			} else {
				logger.Debug().Msg("Set connection write buffer size")
			}
			newClientConn := &ClientConnection{
				Conn:          conn,
				RemoteAddr:    remoteAddr,
				LastKeepAlive: now,
				IsIdle:        false,
			}
			s.clients[clientIdx][localPortIdx] = newClientConn
		} else {
			s.clients[clientIdx][localPortIdx].LastKeepAlive = now
		}
		return gnet.None
	} else {
		logger.Debug().Msg("Ignoring packet with invalid port")
		return gnet.Close
	}
}

func clientIdxFromIP(ip net.IP) int {
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
