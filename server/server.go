package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/xeptore/linkos/config"
)

type Server struct {
	bindAddr    string
	broadcastIP net.IP
	subnetCIDR  *net.IPNet
	bufferSize  int
	bufferPool  *BufferPool
	clients     *Clients
	logger      zerolog.Logger
}

func New(logger zerolog.Logger, subnetCIDR, bindAddr string, bufferSize int) (*Server, error) {
	_, subnetIPNet, err := net.ParseCIDR(subnetCIDR)
	if nil != err {
		return nil, fmt.Errorf("server: error parsing subnet CIDR: %v", err)
	}

	broadcastIP, err := getBroadcastIP(subnetIPNet)
	if nil != err {
		return nil, fmt.Errorf("server: failed to get broadcast IP: %v", err)
	}

	return &Server{
		bindAddr:    bindAddr,
		broadcastIP: broadcastIP,
		subnetCIDR:  subnetIPNet,
		bufferSize:  bufferSize,
		bufferPool:  NewBufferPool(bufferSize),
		clients: &Clients{
			clients: make(map[string]Client, config.DefaultServerInitialClientsCap),
			l:       sync.RWMutex{},
		},
		logger: logger,
	}, nil
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

func (s *Server) Run(ctx context.Context) error {
	serverAddr, err := net.ResolveUDPAddr("udp", s.bindAddr)
	if nil != err {
		return fmt.Errorf("server: failed to resolve bind address: %v", err)
	}

	conn, err := net.ListenUDP("udp", serverAddr)
	if nil != err {
		return fmt.Errorf("server: failed to initialize listener: %v", err)
	}
	defer func() {
		s.logger.Trace().Msg("Closing server listener")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				s.logger.Error().Err(err).Msg("Failed to close server listener")
			}
		} else {
			s.logger.Trace().Msg("Server listener closed")
		}
	}()
	context.AfterFunc(ctx, func() {
		s.logger.Trace().Msg("Closing server listener due to parent context cancellation")
		if err := conn.Close(); nil != err {
			s.logger.Error().Err(err).Msg("Failed to close server listener")
		} else {
			s.logger.Trace().Msg("Server listener closed")
		}
	})

	s.logger.Info().Str("bind_addr", s.bindAddr).Msg("Server is listening")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(config.DefaultServerCleanupIntervalSec * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Trace().Msg("Finishing inactive clients cleanup worker as parent context has been cancelled")
				return
			case <-ticker.C:
				s.logger.Trace().Msg("Running inactive clients cleanup")
				s.clients.cleanupInactive()
			}
		}
	}()
	s.logger.Trace().Msg("Spawned inactive clients cleanup worker")

	buffer := make([]byte, s.bufferSize)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Trace().Msg("Finishing server listener reader as connection has already been closed")
				break
			} else {
				s.logger.Error().Err(err).Msg("Failed to read packet from connection")
			}
			continue
		}
		if n == 0 {
			s.clients.remove(addr)
		}

		buf := s.bufferPool.Get()
		buf.b.Reset()
		buf.b.Write(buffer[:n])
		wg.Add(1)
		go s.handlePacket(conn, &wg, buf, addr)
	}

	s.logger.Trace().Msg("Waiting for all workers to finish")
	wg.Wait()
	s.logger.Trace().Msg("All workers have finished")
	return nil
}

func (s *Server) isInSubnet(ip net.IP) bool {
	return s.subnetCIDR.Contains(ip)
}

func (s *Server) handlePacket(conn *net.UDPConn, wg *sync.WaitGroup, packetBuffer *Buffer, addr *net.UDPAddr) {
	defer wg.Done()
	defer packetBuffer.Return()

	packet := packetBuffer.b.Bytes()
	if l := len(packet); l < 20 {
		s.logger.Debug().Int("bytes", l).Str("from", addr.String()).Msg("Ignoring invalid IP packetBuffer.buf")
		return
	}

	srcIP, dstIP, err := parseIPv4Header(packet)
	if nil != err {
		s.logger.Debug().Err(err).Str("addr", addr.String()).Msg("Failed to parse packet IP header")
		return
	}
	logger := s.logger.With().Str("src_ip", srcIP.String()).Str("dst_ip", dstIP.String()).Logger()
	logger.Debug().Msg("Received packet")

	if !s.isInSubnet(srcIP) || !s.isInSubnet(dstIP) {
		logger.Debug().Msg("Ignoring packet outside of subnet")
		return
	}
	s.clients.set(addr, srcIP)

	if dstIP.Equal(s.broadcastIP) {
		logger.Trace().Msg("Broadcasting packet")
		s.clients.broadcast(logger, conn, srcIP, packet)
	} else {
		logger.Debug().Msg("Received packet")
		s.clients.forward(logger, conn, dstIP, packet)
	}
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
