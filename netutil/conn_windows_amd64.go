package netutil

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/windows"
)

func IsConnClosedError(err error) bool {
	if opErr := new(net.OpError); errors.As(err, &opErr) {
		if sysErr := new(os.SyscallError); errors.As(opErr.Err, &sysErr) {
			if errors.Is(sysErr.Err, windows.WSAEINVAL) && sysErr.Syscall == "wsasend" {
				return true
			}
		}
	}
	return false
}
