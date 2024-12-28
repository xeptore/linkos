package pool

import (
	"github.com/panjf2000/gnet/v2/pkg/pool/byteslice"
)

type Pool struct {
	pool          *byteslice.Pool
	PacketMaxSize int
}

func New(bufferSize int) Pool {
	pool := new(byteslice.Pool)
	return Pool{
		pool:          pool,
		PacketMaxSize: bufferSize,
	}
}

type Packet struct {
	B    []byte
	Size int
	pool *byteslice.Pool
}

func (b *Packet) ReturnToPool() {
	b.B = b.B[:0]
	b.Size = 0
	b.pool.Put(b.B)
}

func (bp *Pool) AcquirePacket(size int) *Packet {
	return &Packet{
		B:    bp.pool.Get(size),
		Size: 0,
		pool: bp.pool,
	}
}
