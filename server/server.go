package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"go.uber.org/zap"

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
		clientConns map[ClientPrivateIP]ClientConns
		logger      zerolog.Logger
	}
	ClientPrivateIP = string
	LocalConnAddr   = string
	ClientConns     map[LocalConnAddr]*ClientConn
	ClientConn      struct {
		Conn          io.WriteCloser
		LastKeepAlive int64
		Disconnected  bool
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
		clientConns:        make(map[ClientPrivateIP]ClientConns, config.DefaultServerInitialAllocatedClients),
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
		for ip, clientConn := range s.clientConns {
			for localConnAddr, conn := range clientConn {
				if err := conn.Conn.Close(); nil != err {
					s.logger.Error().Err(err).Str("local_conn_addr", localConnAddr).Str("ip", ip).Msg("Failed to close client connection")
				}
			}
		}
		s.logger.Debug().Msg("Server engine stopped")
	}()

	opts := []gnet.Option{
		gnet.WithMulticore(false),
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

	protoAddrs := lo.Map(config.DefaultPorts, func(port string, _ int) string { return "udp4://" + net.JoinHostPort(s.bindHost, port) })
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
	for ip, clientConn := range s.clientConns {
		for localConnAddr, conn := range clientConn {
			if now-conn.LastKeepAlive > config.DefaultKeepAliveIntervalSec*config.DefaultMissedKeepAliveThreshold {
				conn.Disconnected = true
				s.logger.Debug().Str("client_ip", ip).Str("local_conn_addr", localConnAddr).Msg("Marked client as disconnected due to passing missed keep-alive threshold")
				if err := conn.Conn.Close(); nil != err {
					s.logger.Error().Err(err).Str("local_conn_addr", localConnAddr).Msg("Failed to close stale client connection")
				} else {
					s.logger.Debug().Str("local_conn_addr", localConnAddr).Msg("Closed stale client connection")
				}
			}
		}
	}
	return s.tick, gnet.None
}

func (s *Server) OnTraffic(c gnet.Conn) gnet.Action {
	packet, err := c.Next(-1)
	if nil != err {
		s.logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to read packet")
		return gnet.Close
	}

	var (
		remoteAddr = c.RemoteAddr().String()
		localAddr  = c.LocalAddr().String()
	)
	logger := s.logger.With().Str("remote_addr", remoteAddr).Str("local_addr", localAddr).Logger()

	if n := c.InboundBuffered(); n > 0 {
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
	}
	prvIP := srcIP.String()
	logger = logger.With().Str("src_ip", prvIP).Str("dst_ip", dstIP.String()).Logger()
	logger.Debug().Msg("Received packet")

	if !s.isInSubnet(srcIP) || !s.isInSubnet(dstIP) {
		logger.Debug().Msg("Ignoring packet outside of subnet")
		return gnet.None
	}

	client, ok := s.clientConns[prvIP]
	if !ok {
		logger.Debug().Msg("New client added")

		if err := c.SetReadBuffer(s.bufferSize); nil != err {
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set read buffer")
		} else {
			logger.Debug().Msg("Set connection read buffer size")
		}
		if err := c.SetWriteBuffer(s.bufferSize); nil != err {
			logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set write buffer")
		} else {
			logger.Debug().Msg("Set connection write buffer size")
		}

		s.clientConns[prvIP] = map[LocalConnAddr]*ClientConn{
			localAddr: {
				Conn:          c,
				LastKeepAlive: time.Now().Unix(),
				Disconnected:  false,
			},
		}
	} else {
		if conn, ok := client[localAddr]; ok {
			if conn.Disconnected {
				logger.Debug().Msg("Reconnected client")

				if err := c.SetReadBuffer(s.bufferSize); nil != err {
					logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set read buffer")
				} else {
					logger.Debug().Msg("Set connection read buffer size")
				}
				if err := c.SetWriteBuffer(s.bufferSize); nil != err {
					logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set write buffer")
				} else {
					logger.Debug().Msg("Set connection write buffer size")
				}

				conn.Conn = c
				conn.Disconnected = false
			}
		} else {
			logger.Debug().Msg("New client connection added")
			if err := c.SetReadBuffer(s.bufferSize); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set read buffer")
			} else {
				logger.Debug().Msg("Set connection read buffer size")
			}
			if err := c.SetWriteBuffer(s.bufferSize); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to set write buffer")
			} else {
				logger.Debug().Msg("Set connection write buffer size")
			}

			client[localAddr] = &ClientConn{
				Conn:          c,
				LastKeepAlive: time.Now().Unix(),
				Disconnected:  false,
			}
		}
	}

	switch {
	case dstIP.Equal(s.gatewayIP):
		logger.Debug().Msg("Handling keep-alive packet")
		s.clientConns[prvIP][localAddr].LastKeepAlive = time.Now().Unix()
		logger.Debug().Msg("Updated client keep-alive timestamp")
	case dstIP.Equal(s.broadcastIP):
		logger.Debug().Msg("Broadcasting packet")

		for ip, clientConn := range s.clientConns {
			if ip == prvIP {
				continue
			}
			logger = logger.With().Str("dst_ip", ip).Logger()
			for localConnAddr, conn := range clientConn {
				if conn.Disconnected {
					logger.Debug().Str("local_conn_addr", localConnAddr).Msg("Skipping disconnected client")
					continue
				}
				logger = logger.With().Str("local_conn_addr", localConnAddr).Logger()
				logger.Debug().Msg("Broadcasting packet to client")
				if _, err := conn.Conn.Write(packet); nil != err {
					logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
				} else {
					logger.Debug().Msg("Broadcasted packet to client")
				}
				break
			}
		}
	default:
		logger.Debug().Msg("Forwarding packet")
		clientConn, ok := s.clientConns[dstIP.String()]
		if !ok {
			logger.Debug().Msg("Client not found")
			return gnet.None
		}
		for localConnAddr, conn := range clientConn {
			if conn.Disconnected {
				logger.Debug().Str("local_conn_addr", localConnAddr).Msg("Skipping disconnected client")
				continue
			}
			logger = logger.With().Str("local_conn_addr", localConnAddr).Logger()
			logger.Debug().Msg("Forwarding packet to client")
			if _, err := conn.Conn.Write(packet); nil != err {
				logger.Error().Err(err).Func(errutil.TreeLog(err)).Msg("Failed to write packet")
			} else {
				logger.Debug().Msg("Forwarding packet to client")
			}
			break
		}
	}

	return gnet.None
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
