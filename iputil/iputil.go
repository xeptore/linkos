package iputil

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

func GatewayIP(ip net.IP, prefixLen int) (net.IP, error) {
	_, network, err := net.ParseCIDR(ip.String() + "/" + strconv.Itoa(prefixLen))
	if nil != err {
		return nil, fmt.Errorf("failed to parse CIDR: %v", err)
	}

	gatewayIP := network.IP.To4().To4()
	if gatewayIP == nil {
		return nil, errors.New("failed to convert to IPv4")
	}
	gatewayIP[3] = 1

	return gatewayIP, nil
}
