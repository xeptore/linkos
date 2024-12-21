/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

func (d *dll) NewProc(name string) *proc {
	return &proc{dll: d, Name: name} //nolint:exhaustruct
}

type proc struct {
	Name string
	mu   sync.Mutex
	dll  *dll
	addr uintptr
}

func (p *proc) Find() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr))) != nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.addr != 0 {
		return nil
	}

	addr, err := p.nameToAddr()
	if nil != err {
		return fmt.Errorf("error getting %s address: %w", p.Name, err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr)), unsafe.Pointer(addr))
	return nil
}

func (p *proc) Addr() uintptr {
	if err := p.Find(); nil != err {
		panic(err)
	}
	return p.addr
}

func (p *proc) nameToAddr() (uintptr, error) {
	return p.dll.module.ProcAddressByName(p.Name)
}

type dll struct {
	Name   string
	Base   windows.Handle
	mu     sync.Mutex
	module *memmod.Module
}

func mustLoadDLL(name string) *dll {
	d := &dll{Name: name} //nolint:exhaustruct
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.module != nil {
		return nil
	}

	module, err := memmod.LoadLibrary(dllContent)
	if nil != err {
		panic(fmt.Errorf("unable to load library: %w", err))
	}
	d.Base = windows.Handle(module.BaseAddr())

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))

	return d
}
