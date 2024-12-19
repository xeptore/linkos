package pool

import (
	"bytes"
	"sync"
)

type PacketPool struct {
	pool          *sync.Pool
	PacketMaxSize int
}

func New(size int) *PacketPool {
	pool := &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, size))
		},
	}
	seed(pool)
	return &PacketPool{pool: pool, PacketMaxSize: size}
}

func seed(p *sync.Pool) {
	for range 100 {
		p.Put(p.New())
	}
}

type Packet struct {
	Payload *bytes.Buffer
	Size    int
	pool    *sync.Pool
}

func (b *Packet) ReturnToPool() {
	b.pool.Put(b.Payload)
}

func (bp *PacketPool) AcquirePacket() *Packet {
	return &Packet{
		Payload: bp.pool.Get().(*bytes.Buffer),
		Size:    0,
		pool:    bp.pool,
	}
}
