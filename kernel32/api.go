//go:build windows && amd64

package kernel32

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = windows.MustLoadDLL("kernel32.dll")
	setEvent               = kernel32.MustFindProc("SetEvent")
	createEventW           = kernel32.MustFindProc("CreateEventW")
	waitForSingleObjectEx  = kernel32.MustFindProc("WaitForSingleObjectEx")
	waitForMultipleObjects = kernel32.MustFindProc("WaitForMultipleObjects")
	closeHandle            = kernel32.MustFindProc("CloseHandle")
)

func WaitForSingleObject(h windows.Handle, timeout uint32) (uint32, error) {
	ret, _, err := waitForSingleObjectEx.Call(uintptr(h), uintptr(timeout), 0)
	return uint32(ret), err
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func WaitForMultipleObjects(handles []windows.Handle, waitAll bool, timeout uint32) (uint32, error) {
	ret, _, err := waitForMultipleObjects.Call(uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), boolToUintptr(waitAll), uintptr(timeout))
	if errors.Is(err, windows.ERROR_SUCCESS) {
		err = nil
	}
	return uint32(ret), err
}

func SetEvent(h windows.Handle) error {
	ret, _, err := setEvent.Call(uintptr(h))
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

	ret, _, err := createEventW.Call(0, boolToUintptr(manualReset), boolToUintptr(initialState), uintptr(unsafe.Pointer(namePtr)))
	if errors.Is(err, windows.ERROR_SUCCESS) {
		err = nil
	}

	return windows.Handle(ret), err
}

func CloseHandle(h windows.Handle) error {
	ret, _, err := closeHandle.Call(uintptr(h))
	if ret == 0 {
		return err
	}
	return nil
}
