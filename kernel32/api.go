//go:build windows && amd64

package kernel32

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                   = windows.MustLoadDLL("kernel32.dll")
	procSetConsoleCtrlHandler  = kernel32.MustFindProc("SetConsoleCtrlHandler")
	procSetEvent               = kernel32.MustFindProc("SetEvent")
	procCreateEventW           = kernel32.MustFindProc("CreateEventW")
	procWaitForSingleObjectEx  = kernel32.MustFindProc("WaitForSingleObjectEx")
	procWaitForMultipleObjects = kernel32.MustFindProc("WaitForMultipleObjects")
	procCloseHandle            = kernel32.MustFindProc("CloseHandle")
)

func WaitForSingleObject(h windows.Handle, timeout uint32) (uint32, error) {
	ret, _, err := procWaitForSingleObjectEx.Call(uintptr(h), uintptr(1), 0)
	if !isErrSuccess(err) {
		return uint32(0), err
	}
	return uint32(ret), nil
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func ctrlHandler(h func()) func(fdwCtrlType uint32) int32 {
	return func(fdwCtrlType uint32) int32 {
		switch fdwCtrlType {
		case
			windows.CTRL_C_EVENT,
			windows.CTRL_CLOSE_EVENT,
			windows.CTRL_BREAK_EVENT,
			windows.CTRL_LOGOFF_EVENT,
			windows.CTRL_SHUTDOWN_EVENT:
			h()
		}
		return 0
	}
}

func isErrSuccess(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == 0 {
			return true
		}
	}
	return false
}

func SetConsoleCtrlHandler(h func()) error {
	handlerRoutine := ctrlHandler(h)
	_, _, err := procSetConsoleCtrlHandler.Call(uintptr(unsafe.Pointer(&handlerRoutine)), uintptr(1))
	if !isErrSuccess(err) {
		return err
	}
	return nil
}

func WaitForMultipleObjects(handles []windows.Handle, waitAll bool, timeout uint32) (uint32, error) {
	ret, _, err := procWaitForMultipleObjects.Call(uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), boolToUintptr(waitAll), uintptr(timeout))
	if errors.Is(err, windows.ERROR_SUCCESS) {
		err = nil
	}
	return uint32(ret), err
}

func SetEvent(h windows.Handle) error {
	ret, _, err := procSetEvent.Call(uintptr(h))
	if ret == 0 {
		return err
	}
	return nil
}

func CreateEvent(manualReset bool, initialState bool, name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if nil != err {
		return 0, err
	}

	ret, _, err := procCreateEventW.Call(0, boolToUintptr(manualReset), boolToUintptr(initialState), uintptr(unsafe.Pointer(namePtr)))
	if errors.Is(err, windows.ERROR_SUCCESS) {
		err = nil
	}

	return windows.Handle(ret), err
}

func CloseHandle(h windows.Handle) error {
	ret, _, err := procCloseHandle.Call(uintptr(h))
	if ret == 0 {
		return err
	}
	return nil
}
