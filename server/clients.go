package server

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/xeptore/linkos/config"
)

type Clients struct {
	clients map[string]Client
	l       sync.RWMutex
}

type Client struct {
	addr       *net.UDPAddr
	lastActive int64
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
	now := time.Now().Unix()

	c.l.Lock()
	for ip, client := range c.clients {
		if now-client.lastActive > config.DefaultServerInactiveConnectionEvictionSec {
			delete(c.clients, ip)
		}
	}
	c.l.Unlock()
}

func (c *Clients) set(addr *net.UDPAddr, srcIP net.IP) {
	srcIPStr := srcIP.String()
	newClient := Client{
		addr:       addr,
		lastActive: time.Now().Unix(),
	}

	c.l.Lock()
	if client, ok := c.clients[srcIPStr]; !ok || client.addr != addr {
		c.clients[srcIPStr] = newClient
	}
	c.l.Unlock()
}

func (c *Clients) broadcast(logger *logrus.Logger, conn *net.UDPConn, srcIP net.IP, packet []byte) {
	srcIPStr := srcIP.String()

	c.l.RLock()
	dstAddrs := make([]*net.UDPAddr, 0, len(c.clients)-1)
	for dstIP, dstClient := range c.clients {
		if srcIPStr != dstIP {
			dstAddrs = append(dstAddrs, dstClient.addr)
		}
	}
	c.l.RUnlock()

	for _, dstAddr := range dstAddrs {
		dstIP := dstAddr.IP.String()
		if _, err := conn.WriteToUDP(packet, dstAddr); nil != err {
			logger.
				WithFields(
					logrus.Fields{
						"src_ip": srcIPStr,
						"dst_ip": dstIP,
					},
				).
				WithError(err).
				Error("Failed to broadcast packet")
		} else {
			logger.WithFields(logrus.Fields{"src_ip": srcIPStr, "dst_ip": dstIP}).Trace("Broadcasted packet")
		}
	}
}

func (c *Clients) forward(logger *logrus.Logger, conn *net.UDPConn, dstIP net.IP, packet []byte) {
	dstIPStr := dstIP.String()

	c.l.RLock()
	dstClient, exists := c.clients[dstIPStr]
	if !exists {
		c.l.RUnlock()
		return
	}
	c.l.RUnlock()

	if _, err := conn.WriteToUDP(packet, dstClient.addr); nil != err {
		logger.WithField("dst_ip", dstIPStr).Error("Failed to forward packet")
	} else {
		logger.WithField("dst_ip", dstIPStr).Trace("Forwarded packet")
	}
}
