package pool

import (
	"bytes"
	"sync"
)

type Pool struct {
	pool          *sync.Pool
	PacketMaxSize int
}

func New(bufferSize int) Pool {
	pool := &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, bufferSize))
		},
	}
	seed(pool)
	return Pool{pool: pool, PacketMaxSize: bufferSize}
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
	b.Payload.Reset()
	b.Size = 0
	b.pool.Put(b.Payload)
}

func (bp *Pool) AcquirePacket() *Packet {
	return &Packet{
		Payload: bp.pool.Get().(*bytes.Buffer),
		Size:    0,
		pool:    bp.pool,
	}
}
