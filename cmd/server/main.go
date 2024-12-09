package main

import (
	"log"
	"net"
	"sync"
)

const (
	serverAddress = ":5000"
	bufferSize    = 4096
	vpnSubnetCIDR = "10.0.0.0/24"
)

type Client struct {
	Address *net.UDPAddr
	IP      net.IP
}

var (
	clients     = make(map[string]*Client)
	clientsLock = sync.Mutex{}
	broadcastIP = net.ParseIP("10.0.0.255")
)

func main() {
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	if nil != err {
		log.Fatalf("Failed to resolve server address: %v", err)
	}

	conn, err := net.ListenUDP("udp", serverAddr)
	if nil != err {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer conn.Close()

	log.Printf("Server listening on %s", serverAddress)

	buffer := make([]byte, bufferSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if nil != err {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		go handlePacket(conn, buffer[:n], clientAddr)
	}
}

func handlePacket(conn *net.UDPConn, packet []byte, clientAddr *net.UDPAddr) {
	if len(packet) < 20 {
		log.Printf("Invalid IP packet from %s", clientAddr)
		return
	}

	srcIP, destIP, protocol := parseIPHeader(packet)
	if srcIP == nil || destIP == nil {
		log.Printf("Failed to parse IP header from %s", clientAddr)
		return
	}

	clientsLock.Lock()
	defer clientsLock.Unlock()

	srcKey := srcIP.String()
	if _, exists := clients[srcKey]; !exists {
		clients[srcKey] = &Client{
			Address: clientAddr,
			IP:      srcIP,
		}
		log.Printf("Registered client %s with IP %s", clientAddr, srcIP)
	}

	log.Printf("Packet protocol: %d from %s to %s", protocol, srcIP, destIP)

	if destIP.Equal(broadcastIP) {
		log.Printf("Broadcast packet from %s", srcIP)
		for ipStr, c := range clients {
			if ipStr != srcKey {
				_, err := conn.WriteToUDP(packet, c.Address)
				if nil != err {
					log.Printf("Error broadcasting to %s: %v", c.IP, err)
				}
			}
		}
	} else {
		destKey := destIP.String()
		if destClient, exists := clients[destKey]; exists {
			_, err := conn.WriteToUDP(packet, destClient.Address)
			if nil != err {
				log.Printf("Error forwarding packet to %s: %v", destIP, err)
			} else {
				log.Printf("Forwarded packet from %s to %s", srcIP, destIP)
			}
		} else {
			log.Printf("Unknown destination IP %s, dropping packet", destIP)
		}
	}
}

// parseIPHeader parses the IP header from an IPv4 packet.
// Returns source IP, destination IP, and the protocol number.
// IPv4 header format: https://tools.ietf.org/html/rfc791
func parseIPHeader(packet []byte) (srcIP, destIP net.IP, protocol uint8) {
	// IP version & IHL are in the first byte
	// Check version == 4
	versionIHL := packet[0]
	version := versionIHL >> 4
	if version != 4 {
		return nil, nil, 0
	}

	protocol = packet[9]

	srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15])
	destIP = net.IPv4(packet[16], packet[17], packet[18], packet[19])
	return srcIP, destIP, protocol
}
