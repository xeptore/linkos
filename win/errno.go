package win

import (
	"errors"
	"syscall"
)

func IsErrSuccess(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == 0 {
			return true
		}
	}
	return false
}
