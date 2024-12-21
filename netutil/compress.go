package netutil

import (
	"bytes"
	"fmt"

	"github.com/pierrec/lz4/v4"
)

func Compress(packet []byte) ([]byte, error) {
	var compressedData bytes.Buffer
	w := lz4.NewWriter(&compressedData)
	if _, err := w.Write(packet); nil != err {
		return nil, fmt.Errorf("netutil: failed to write compressed data: %v", err)
	}
	if err := w.Close(); nil != err {
		return nil, fmt.Errorf("netutil: failed to close compressed data: %v", err)
	}
	return compressedData.Bytes(), nil
}

func Decompress(packet []byte) ([]byte, error) {
	var decompressedData bytes.Buffer
	if _, err := decompressedData.ReadFrom(lz4.NewReader(bytes.NewReader(packet))); nil != err {
		return nil, fmt.Errorf("netutil: failed to read decompressed data: %v", err)
	}
	return decompressedData.Bytes(), nil
}
