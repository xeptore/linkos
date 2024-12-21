package packet

import (
	"bytes"
	"fmt"

	"github.com/pierrec/lz4/v4"
)

func (p *Packet) compressed() ([]byte, error) {
	var compressedData bytes.Buffer
	w := lz4.NewWriter(&compressedData)
	if _, err := w.Write(p.Raw); nil != err {
		return nil, fmt.Errorf("netutil: failed to write compressed payload: %v", err)
	}
	if err := w.Close(); nil != err {
		return nil, fmt.Errorf("netutil: failed to close compressed payload: %v", err)
	}
	return compressedData.Bytes(), nil
}

func Decompress(p []byte) ([]byte, error) {
	var decompressedData bytes.Buffer
	if _, err := decompressedData.ReadFrom(lz4.NewReader(bytes.NewReader(p))); nil != err {
		return nil, fmt.Errorf("netutil: failed to read decompressed payload: %v", err)
	}
	return decompressedData.Bytes(), nil
}
