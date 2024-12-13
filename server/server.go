package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/xeptore/linkos/config"
)

type Server struct {
	bindAddr    string
	broadcastIP net.IP
	subnetCIDR  *net.IPNet
	bufferSize  int
	bufferPool  *BufferPool
	clients     *Clients
	logger      *logrus.Logger
}

func New(logger *logrus.Logger, subnetCIDR, bindAddr string, bufferSize int) (*Server, error) {
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
		s.logger.Trace("Closing server listener")
		if err := conn.Close(); nil != err {
			if !errors.Is(err, net.ErrClosed) {
				s.logger.WithError(err).Error("Failed to close server listener")
			}
		} else {
			s.logger.Trace("Server listener closed")
		}
	}()
	context.AfterFunc(ctx, func() {
		s.logger.Trace("Closing server listener due to parent context cancellation")
		if err := conn.Close(); nil != err {
			s.logger.WithError(err).Error("Failed to close server listener")
		} else {
			s.logger.Trace("Server listener closed")
		}
	})

	s.logger.WithField("bind_addr", s.bindAddr).Info("Server is listening")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(config.DefaultServerCleanupIntervalSec)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Trace("Finishing inactive clients cleanup worker as parent context has been cancelled")
				return
			case <-ticker.C:
				s.logger.Trace("Running inactive clients cleanup")
				s.clients.cleanupInactive()
			}
		}
	}()
	s.logger.Trace("Spawned inactive clients cleanup worker")

	buffer := make([]byte, s.bufferSize)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Trace("Finishing server listener reader as connection has already been closed")
				break
			} else {
				s.logger.WithError(err).Error("Failed to read packet from connection")
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

	s.logger.Trace("Waiting for all workers to finish")
	wg.Wait()
	s.logger.Trace("All workers have finished")
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
		s.logger.WithField("bytes", l).WithField("from", addr.String()).Debug("Ignoring invalid IP packetBuffer.buf")
		return
	}

	srcIP, dstIP, err := parseIPv4Header(packet)
	if nil != err {
		s.logger.WithError(err).Debug("Failed to parse packet IP header", addr)
		return
	}
	s.logger.
		WithFields(logrus.Fields{
			"src_ip": srcIP,
			"dst_ip": dstIP,
		}).
		Debug("Received packet")

	if !s.isInSubnet(srcIP) || !s.isInSubnet(dstIP) {
		s.logger.
			WithFields(logrus.Fields{
				"src_ip": srcIP.String(),
				"dst_ip": dstIP.String(),
			}).
			Debug("Ignoring packet outside of subnet")
		return
	}
	s.clients.set(addr, srcIP)

	if dstIP.Equal(s.broadcastIP) {
		s.logger.WithField("src_ip", srcIP.String()).Trace("Broadcasting packet")
		s.clients.broadcast(s.logger, conn, srcIP, packet)
	} else {
		s.logger.
			WithFields(
				logrus.Fields{
					"src_ip": srcIP.String(),
					"dst_ip": dstIP.String(),
				},
			).
			Debug("Forwarding packet")
		s.clients.forward(s.logger, conn, dstIP, packet)
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
