package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

// TODO: add cleanup routine that cleans up clients that were inactive for a certain period of time
// TODO: add buffer pool for received packet cloning

type Server struct {
	bindAddr    string
	broadcastIP net.IP
	subnetCIDR  *net.IPNet
	bufferSize  int
	clients     *Clients
	logger      *logrus.Logger
}

type Clients struct {
	clients map[string]*net.UDPAddr
	l       sync.Mutex
}

func (c *Clients) remove(addr *net.UDPAddr) {
	c.l.Lock()
	defer c.l.Unlock()

	for ip, ad := range c.clients {
		if ad == addr {
			delete(c.clients, ip)
			return
		}
	}
}

func (c *Clients) set(addr *net.UDPAddr, srcIP net.IP) {
	c.l.Lock()
	defer c.l.Unlock()

	srcIPStr := srcIP.String()
	c.clients[srcIPStr] = addr
}

func (c *Clients) broadcast(logger *logrus.Logger, conn *net.UDPConn, srcIP net.IP, packet []byte) {
	c.l.Lock()
	defer c.l.Unlock()

	srcIPStr := srcIP.String()
	for dstIP, dstAddr := range c.clients {
		if srcIPStr != dstIP {
			if _, err := conn.WriteToUDP(packet, dstAddr); nil != err {
				logger.
					WithFields(
						logrus.Fields{
							"src_ip": srcIPStr,
							"dst_ip": dstIP,
						},
					).
					WithError(err).
					Error("failed to broadcast packet")
			}
		}
	}
}

func (c *Clients) forward(logger *logrus.Logger, conn *net.UDPConn, dstIP net.IP, packet []byte) {
	c.l.Lock()
	defer c.l.Unlock()

	dstIPStr := dstIP.String()
	if dstAddr, exists := c.clients[dstIPStr]; exists {
		if _, err := conn.WriteToUDP(packet, dstAddr); nil != err {
			logger.WithField("dst_ip", dstIPStr).Error("failed to forward packet")
		}
	}
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
		clients:     &Clients{clients: make(map[string]*net.UDPAddr), l: sync.Mutex{}},
		logger:      logger,
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

	buffer := make([]byte, s.bufferSize)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if nil != err {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Trace("Finishing server listener reader as connection has already been closed")
				return nil
			} else {
				s.logger.WithError(err).Error("Failed to read packet from connection")
			}
			continue
		}
		if n == 0 {
			s.clients.remove(addr)
		}

		// TODO: clone the packet as buffer is reused but packet is sent to other goroutines
		go s.handlePacket(conn, buffer[:n], addr)
	}
}

func (s *Server) isInSubnet(ip net.IP) bool {
	return s.subnetCIDR.Contains(ip)
}

func (s *Server) handlePacket(conn *net.UDPConn, packet []byte, addr *net.UDPAddr) {
	if l := len(packet); l < 20 {
		s.logger.WithField("bytes", l).WithField("from", addr.String()).Warn("Ignoring invalid IP packet")
		return
	}

	srcIP, dstIP, err := parseIPv4Header(packet)
	if nil != err {
		s.logger.WithError(err).Error("Failed to parse packet IP header", addr)
		return
	}
	s.logger.
		WithFields(logrus.Fields{
			"src_ip": srcIP,
			"dst_ip": dstIP,
		}).
		Trace("Received packet")

	if !s.isInSubnet(srcIP) || !s.isInSubnet(dstIP) {
		s.logger.
			WithFields(logrus.Fields{
				"src_ip": srcIP.String(),
				"dst_ip": dstIP.String(),
			}).
			Warn("Ignoring packet outside of subnet")
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
			Trace("Forwarding packet")
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
