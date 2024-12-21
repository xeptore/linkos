//go:build windows && amd64

package kernel32

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xeptore/linkos/win"
)

var (
	kernel32                   = windows.MustLoadDLL("kernel32.dll")
	procSetEvent               = kernel32.MustFindProc("SetEvent")
	procCreateEventW           = kernel32.MustFindProc("CreateEventW")
	procWaitForSingleObjectEx  = kernel32.MustFindProc("WaitForSingleObjectEx")
	procWaitForMultipleObjects = kernel32.MustFindProc("WaitForMultipleObjects")
	procCloseHandle            = kernel32.MustFindProc("CloseHandle")
)

func WaitForSingleObject(h windows.Handle, timeout uint32) (uint32, error) {
	r1, _, err := procWaitForSingleObjectEx.Call(uintptr(h), uintptr(1), 0)
	if !win.IsErrSuccess(err) {
		return uint32(0), err
	}
	return uint32(r1), nil
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func WaitForMultipleObjects(handles []windows.Handle, waitAll bool, timeout uint32) (uint32, error) {
	r1, _, err := procWaitForMultipleObjects.Call(uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), boolToUintptr(waitAll), uintptr(timeout))
	if !win.IsErrSuccess(err) {
		return 0, err
	}
	return uint32(r1), nil
}

func SetEvent(h windows.Handle) error {
	if _, _, err := procSetEvent.Call(uintptr(h)); !win.IsErrSuccess(err) {
		return err
	}
	return nil
}

func CreateEvent(manualReset bool, initialState bool, name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if nil != err {
		return 0, err
	}

	r1, _, err := procCreateEventW.Call(0, boolToUintptr(manualReset), boolToUintptr(initialState), uintptr(unsafe.Pointer(namePtr)))
	if !win.IsErrSuccess(err) {
		return 0, err
	}

	return windows.Handle(r1), nil
}

func CloseHandle(h windows.Handle) error {
	if _, _, err := procCloseHandle.Call(uintptr(h)); !win.IsErrSuccess(err) {
		return err
	}
	return nil
}
