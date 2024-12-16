package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/logging"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog"
	"go.uber.org/zap"

	"github.com/xeptore/linkos/config"
	"github.com/xeptore/linkos/errutil"
	"github.com/xeptore/linkos/iputil"
)

type (
	Server struct {
		gnet.BuiltinEventEngine
		engine      gnet.Engine
		bindAddr    string
		bindDev     string
		bufferSize  int
		broadcastIP net.IP
		gatewayIP   net.IP
		subnetIPNet *net.IPNet
		tick        time.Duration
		clients     *xsync.MapOf[ClientPrivateIP, *Client]
		logger      zerolog.Logger
	}
	ClientPrivateIP = string
	Client          struct {
		Addr          string
		Conn          gnet.Conn
		LastKeepAlive int64
		Disconnected  bool
		l             *xsync.RBMutex
	}
)

func NewServer(logger zerolog.Logger, ipNet, bindAddr, bindDev string, bufferSize int) (*Server, error) {
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
		bindAddr:           bindAddr,
		bindDev:            bindDev,
		bufferSize:         bufferSize,
		broadcastIP:        broadcastIP,
		gatewayIP:          gatewayIP,
		subnetIPNet:        subnetIPNet,
		tick:               config.DefaultServerCleanupIntervalSec * time.Second,
		clients:            xsync.NewMapOf[ClientPrivateIP, *Client](xsync.WithPresize(config.DefaultServerInitialAllocatedClients), xsync.WithGrowOnly()),
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
			s.logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to stop server engine")
		} else {
			s.logger.Debug().Msg("Server engine stopped")
		}
	}()

	opts := []gnet.Option{
		gnet.WithMulticore(true),
		gnet.WithNumEventLoop(config.DefaultServerInitialAllocatedClients),
		gnet.WithLoadBalancing(gnet.SourceAddrHash),
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
	if err := gnet.Run(s, "udp4://"+s.bindAddr, opts...); nil != err {
		if errors.Is(err, ctx.Err()) {
			s.logger.Debug().Msg("Server engine stopped due to context error. Waiting for server engine stopper goroutine to return")
			wg.Wait()
			s.logger.Debug().Msg("Server engine stopper goroutine returned")
			return err
		}
		s.logger.Debug().Err(err).Msg("Server engine stopped due to unknown error. Waiting for server engine stopper goroutine to return")
		cancel()
		wg.Wait()
		s.logger.Debug().Msg("Server engine stopper goroutine returned")
		return fmt.Errorf("server: failed to run server: %w", err)
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
	s.clients.Range(func(ip string, client *Client) bool {
		client.l.Lock()
		if now-client.LastKeepAlive > config.DefaultKeepAliveIntervalSec*config.DefaultMissedKeepAliveThreshold {
			client.Disconnected = true
		}
		client.l.Unlock()
		return true
	})
	return s.tick, gnet.None
}

func (s *Server) OnTraffic(c gnet.Conn) gnet.Action {
	packet, err := c.Next(-1)
	if nil != err {
		s.logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to read packet")
		return gnet.Close
	}

	srcAddr := c.RemoteAddr().String()
	logger := s.logger.With().Str("src_addr", srcAddr).Logger()

	if l := len(packet); l < 20 {
		s.logger.Debug().Int("bytes", l).Msg("Ignoring invalid IP packet")
		return gnet.None
	} else {
		logger = logger.With().Int("bytes", l).Logger()
	}

	srcIP, dstIP, err := parseIPv4Header(packet)
	if nil != err {
		s.logger.Debug().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to parse packet IP header")
		return gnet.None
	}
	prvIP := srcIP.String()
	logger = logger.With().Str("src_ip", prvIP).Str("dst_ip", dstIP.String()).Logger()
	logger.Debug().Msg("Received packet")

	if !s.isInSubnet(srcIP) || !s.isInSubnet(dstIP) {
		logger.Debug().Msg("Ignoring packet outside of subnet")
		return gnet.None
	}

	client, existed := s.clients.LoadOrStore(
		prvIP,
		&Client{
			Addr:          srcAddr,
			Conn:          c,
			LastKeepAlive: time.Now().Unix(),
			Disconnected:  false,
			l:             xsync.NewRBMutex(),
		},
	)
	if existed {
		logger.Debug().Msg("Client already exists")
		newClient := &Client{
			Addr:          srcAddr,
			Conn:          c,
			LastKeepAlive: time.Now().Unix(),
			Disconnected:  false,
			l:             xsync.NewRBMutex(),
		}

		tk := client.l.RLock()
		isDisconnected := client.Disconnected
		client.l.RUnlock(tk)

		if isDisconnected || client.Addr != srcAddr {
			logger.
				Debug().
				Bool("is_disconnected", isDisconnected).
				Str("stored_client_addr", client.Addr).
				Msg("Replacing existing client")
			s.clients.Store(prvIP, newClient)
		}
	} else {
		if err := c.SetReadBuffer(s.bufferSize); nil != err {
			logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to set read buffer")
		} else {
			logger.Debug().Msg("Set connection read buffer size")
		}

		if err := c.SetWriteBuffer(s.bufferSize); nil != err {
			logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to set write buffer")
		} else {
			logger.Debug().Msg("Set connection write buffer size")
		}
	}

	switch {
	case dstIP.Equal(s.subnetIPNet.IP):
		logger.Debug().Msg("Handling keep-alive packet")
		client.l.Lock()
		client.LastKeepAlive = time.Now().Unix()
		client.l.Unlock()
		logger.Debug().Msg("Updated client keep-alive timestamp")
	case dstIP.Equal(s.broadcastIP):
		logger.Debug().Msg("Broadcasting packet")
		s.clients.Range(func(ip string, client *Client) bool {
			if ip != srcIP.String() {
				logger = logger.With().Str("dst_ip", ip).Str("dst_addr", client.Addr).Logger()
				logger.Debug().Msg("Broadcasting packet to client")
				if _, err := client.Conn.Write(packet); nil != err {
					logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to write packet")
				} else {
					logger.Debug().Msg("Broadcasted packet to client")
				}
			}
			return true
		})
	default:
		logger.Debug().Msg("Received packet")
		if client, ok := s.clients.Load(dstIP.String()); ok {
			logger.Debug().Msg("Forwarding packet to client")
			if _, err := client.Conn.Write(packet); nil != err {
				logger.Error().Err(err).Dict("err_tree", errutil.Tree(err).LogDict()).Msg("Failed to write packet")
			} else {
				logger.Debug().Msg("Forwarded packet to client")
			}
		}
	}

	return gnet.None
}

// IPv4 header format: https://tools.ietf.org/html/rfc791
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
