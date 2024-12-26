package server

import (
	"io"
)

type DiscardConn struct{}

func (DiscardConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (DiscardConn) Close() error {
	return nil
}

var Discard io.WriteCloser = DiscardConn{}
