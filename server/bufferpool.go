package server

import (
	"bytes"
	"sync"

	"github.com/xeptore/linkos/config"
)

type BufferPool struct {
	pool *sync.Pool
}

func NewBufferPool(bufferSize int) *BufferPool {
	pool := &sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 0, bufferSize))
		},
	}
	seedBufferPool(pool)
	return &BufferPool{pool}
}

func seedBufferPool(pool *sync.Pool) {
	for range config.DefaultServerBufferPoolInitialSeeds {
		pool.Put(pool.New())
	}
}

type Buffer struct {
	b    *bytes.Buffer
	pool *sync.Pool
}

func (b *Buffer) Return() {
	b.pool.Put(b.b)
}

func (bp *BufferPool) Get() *Buffer {
	return &Buffer{
		b:    bp.pool.Get().(*bytes.Buffer),
		pool: bp.pool,
	}
}
