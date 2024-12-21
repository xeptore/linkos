/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xeptore/linkos/win"
)

type Adapter struct {
	handle uintptr
}

var (
	modwintun                = mustLoadDLL("wintun.dll")
	procWintunCreateAdapter  = modwintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter    = modwintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter   = modwintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver   = modwintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID = modwintun.NewProc("WintunGetAdapterLUID")
)

func closeAdapter(wintun *Adapter) {
	syscall.SyscallN(procWintunCloseAdapter.Addr(), wintun.handle, 0, 0) //nolint:errcheck
}

// CreateAdapter creates a Wintun adapter. name is the cosmetic name of the adapter.
// tunnelType represents the type of adapter and should be "Wintun". requestedGUID is
// the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random,
// and hence a new NLA entry is created for each new adapter.
func CreateAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (*Adapter, error) {
	var name16 *uint16
	name16, err := windows.UTF16PtrFromString(name)
	if nil != err {
		return nil, err
	}

	var tunnelType16 *uint16
	tunnelType16, err = windows.UTF16PtrFromString(tunnelType)
	if nil != err {
		return nil, err
	}

	r1, _, err := syscall.SyscallN(procWintunCreateAdapter.Addr(), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(tunnelType16)), uintptr(unsafe.Pointer(requestedGUID)))
	if r1 == 0 || !win.IsErrSuccess(err) {
		return nil, err
	}

	wintun := &Adapter{handle: r1}
	runtime.SetFinalizer(wintun, closeAdapter)
	return wintun, nil
}

// OpenAdapter opens an existing Wintun adapter by name.
func OpenAdapter(name string) (*Adapter, error) {
	var name16 *uint16
	name16, err := windows.UTF16PtrFromString(name)
	if nil != err {
		return nil, err
	}

	r1, _, err := syscall.SyscallN(procWintunOpenAdapter.Addr(), uintptr(unsafe.Pointer(name16)), 0, 0)
	if r1 == 0 || !win.IsErrSuccess(err) {
		return nil, err
	}

	wintun := &Adapter{handle: r1}
	runtime.SetFinalizer(wintun, closeAdapter)
	return wintun, nil
}

// Close closes a Wintun adapter.
func (wintun *Adapter) Close() error {
	runtime.SetFinalizer(wintun, nil)

	r1, _, err := syscall.SyscallN(procWintunCloseAdapter.Addr(), wintun.handle, 0, 0)
	if r1 == 0 || !win.IsErrSuccess(err) {
		return err
	}
	return nil
}

// Uninstall removes the driver from the system if no drivers are currently in use.
func Uninstall() error {
	r1, _, err := syscall.SyscallN(procWintunDeleteDriver.Addr(), 0, 0, 0)
	if r1 == 0 || !win.IsErrSuccess(err) {
		return err
	}
	return nil
}

// RunningVersion returns the version of the running Wintun driver.
func RunningVersion() (string, error) {
	resInfo, err := windows.FindResource(modwintun.Base, windows.ResourceID(1), windows.RT_VERSION)
	if nil != err {
		return "", fmt.Errorf("wintun: failed to find RT_VERSION resource by ID: %v", err)
	}
	data, err := windows.LoadResourceData(modwintun.Base, resInfo)
	if nil != err {
		return "", fmt.Errorf("wintun: failed to load RT_VERSION resource: %v", err)
	}

	var fixedInfo *windows.VS_FIXEDFILEINFO
	fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
	if err = windows.VerQueryValue(unsafe.Pointer(&data[0]), `\`, unsafe.Pointer(&fixedInfo), &fixedInfoLen); nil != err {
		return "", fmt.Errorf("wintun: failed to query version value from resource: %v", err)
	}
	version := fmt.Sprintf("%d.%d", (fixedInfo.FileVersionMS>>16)&0xff, (fixedInfo.FileVersionMS>>0)&0xff)
	if nextNibble := (fixedInfo.FileVersionLS >> 16) & 0xff; nextNibble != 0 {
		version += fmt.Sprintf(".%d", nextNibble)
	}
	if nextNibble := (fixedInfo.FileVersionLS >> 0) & 0xff; nextNibble != 0 {
		version += fmt.Sprintf(".%d", nextNibble)
	}

	return version, nil
}

// LUID returns the LUID of the adapter.
func (wintun *Adapter) LUID() (luid uint64) {
	syscall.SyscallN(procWintunGetAdapterLUID.Addr(), wintun.handle, uintptr(unsafe.Pointer(&luid)), 0) //nolint:errcheck
	return
}
