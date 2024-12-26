package server

import (
	"net"
	"testing"
)

func TestClientIdxFromIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ip   string
		want int
	}{
		{
			ip:   "10.0.0.2",
			want: 0,
		},
		{
			ip:   "10.0.0.3",
			want: 1,
		},
		{
			ip:   "10.0.0.4",
			want: 2,
		},
		{
			ip:   "10.0.0.5",
			want: 3,
		},
		{
			ip:   "10.0.0.6",
			want: 4,
		},
		{
			ip:   "10.0.0.7",
			want: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			t.Parallel()

			if got := clientIdxFromIP(net.ParseIP(tt.ip).To4()); got != tt.want {
				t.Errorf("ClientIdxFromIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
