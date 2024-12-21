package packet

import (
	"fmt"
	"io"
	"net"
)

type Packet struct {
	Header Header
	Raw    []byte
}

type Header struct {
	SrcIP net.IP
	DstIP net.IP
}

func FromIncoming(b []byte) (*Packet, error) {
	if l := len(b); l < 8 {
		return nil, fmt.Errorf("packet: invalid packet size %d", l)
	}

	p := new(Packet)
	copy(p.Header.SrcIP, b[:4])
	copy(p.Header.DstIP, b[4:8])
	copy(p.Raw, b[8:])
	return p, nil
}

func FromIP(b []byte) (*Packet, error) {
	if l := len(b); l < 20 {
		return nil, fmt.Errorf("packet: invalid packet size %d", l)
	}

	version := b[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("packet: unsupported version %d", version)
	}

	srcIP := net.IPv4(b[12], b[13], b[14], b[15])
	dstIP := net.IPv4(b[16], b[17], b[18], b[19])

	p := new(Packet)
	p.Header.SrcIP = srcIP
	p.Header.DstIP = dstIP
	p.Raw = b
	return p, nil
}

func (p *Packet) Write(w io.Writer) (int, error) {
	comp, err := p.compressed()
	if nil != err {
		return 0, err
	}
	buf := make([]byte, 4+4+len(comp))
	copy(buf[:4], p.Header.SrcIP[:])
	copy(buf[4:8], p.Header.DstIP[:])
	copy(buf[8:], comp)
	return w.Write(buf)
}
