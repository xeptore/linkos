package pool

import (
	"github.com/valyala/bytebufferpool"
)

type Pool struct {
	pool          *bytebufferpool.Pool
	PacketMaxSize int
}

func New(bufferSize int) Pool {
	pool := new(bytebufferpool.Pool)
	seed(pool, bufferSize)
	return Pool{
		pool:          pool,
		PacketMaxSize: bufferSize,
	}
}

func seed(p *bytebufferpool.Pool, bufferSize int) {
	var (
		bufs  = make([]*bytebufferpool.ByteBuffer, 0, 100)
		whole = make([]byte, 100*bufferSize)
	)
	for i := range 100 {
		buf := p.Get()
		buf.Set(whole[i*100 : (i+1)*100])
		bufs = append(bufs, buf)
	}
	for i := range 100 {
		p.Put(bufs[i])
	}
}

type Packet struct {
	Buf  *bytebufferpool.ByteBuffer
	Size int
	pool *bytebufferpool.Pool
}

func (b *Packet) ReturnToPool() {
	b.Buf.Reset()
	b.Size = 0
	b.pool.Put(b.Buf)
}

func (bp *Pool) AcquirePacket() *Packet {
	return &Packet{
		Buf:  bp.pool.Get(),
		Size: 0,
		pool: bp.pool,
	}
}
