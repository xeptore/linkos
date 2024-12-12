package server

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type Clients struct {
	clients map[string]Client
	l       sync.Mutex
}

type Client struct {
	addr       *net.UDPAddr
	lastActive time.Time
}

func (c *Clients) remove(addr *net.UDPAddr) {
	c.l.Lock()
	defer c.l.Unlock()

	for ip, client := range c.clients {
		if client.addr == addr {
			delete(c.clients, ip)
			return
		}
	}
}

func (c *Clients) cleanupInactive() {
	c.l.Lock()
	defer c.l.Unlock()

	for ip, client := range c.clients {
		if time.Since(client.lastActive) > 10*time.Second {
			delete(c.clients, ip)
		}
	}
}

func (c *Clients) set(addr *net.UDPAddr, srcIP net.IP) {
	c.l.Lock()
	defer c.l.Unlock()

	srcIPStr := srcIP.String()
	c.clients[srcIPStr] = Client{
		addr:       addr,
		lastActive: time.Now(),
	}
}

func (c *Clients) broadcast(logger *logrus.Logger, conn *net.UDPConn, srcIP net.IP, packet []byte) {
	c.l.Lock()
	defer c.l.Unlock()

	srcIPStr := srcIP.String()
	for dstIP, dstClient := range c.clients {
		if srcIPStr != dstIP {
			if _, err := conn.WriteToUDP(packet, dstClient.addr); nil != err {
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
	if dstClient, exists := c.clients[dstIPStr]; exists {
		if _, err := conn.WriteToUDP(packet, dstClient.addr); nil != err {
			logger.WithField("dst_ip", dstIPStr).Error("failed to forward packet")
		}
	}
}
