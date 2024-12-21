/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xeptore/linkos/win"
)

type Session struct {
	handle uintptr
}

const (
	PacketSizeMax   = 0xffff    // Maximum packet size
	RingCapacityMin = 0x20000   // Minimum ring capacity (128 kiB)
	RingCapacityMax = 0x4000000 // Maximum ring capacity (64 MiB)
)

// Packet with data.
type Packet struct {
	Next *Packet              // Pointer to next packet in queue
	Size uint32               // Size of packet (max WINTUN_MAX_IP_PACKET_SIZE)
	Data *[PacketSizeMax]byte // Pointer to layer 3 IPv4 or IPv6 packet
}

var (
	procWintunAllocateSendPacket   = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunEndSession           = modwintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent     = modwintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket        = modwintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modwintun.NewProc("WintunReleaseReceivePacket")
	procWintunSendPacket           = modwintun.NewProc("WintunSendPacket")
	procWintunStartSession         = modwintun.NewProc("WintunStartSession")
)

func (wintun *Adapter) StartSession(capacity uint32) (Session, error) {
	r1, _, err := syscall.SyscallN(procWintunStartSession.Addr(), wintun.handle, uintptr(capacity), 0)
	if r1 == 0 || !win.IsErrSuccess(err) {
		return Session{}, err
	}
	return Session{r1}, nil
}

func (session *Session) End() {
	syscall.SyscallN(procWintunEndSession.Addr(), session.handle, 0, 0) //nolint:errcheck
	session.handle = 0
}

func (session *Session) ReadWaitEvent() windows.Handle {
	r1, _, _ := syscall.SyscallN(procWintunGetReadWaitEvent.Addr(), session.handle, 0, 0)
	return windows.Handle(r1)
}

func (session *Session) ReceivePacket() ([]byte, error) {
	var packetSize uint32
	r1, _, err := syscall.SyscallN(procWintunReceivePacket.Addr(), session.handle, uintptr(unsafe.Pointer(&packetSize)), 0)
	if r1 == 0 || !win.IsErrSuccess(err) {
		return nil, err
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(r1)), packetSize), nil
}

func (session *Session) ReleaseReceivePacket(packet []byte) {
	syscall.SyscallN(procWintunReleaseReceivePacket.Addr(), session.handle, uintptr(unsafe.Pointer(&packet[0])), 0) //nolint:errcheck
}

func (session *Session) AllocateSendPacket(packetSize int) ([]byte, error) {
	r1, _, err := syscall.SyscallN(procWintunAllocateSendPacket.Addr(), session.handle, uintptr(packetSize), 0)
	if r1 == 0 || !win.IsErrSuccess(err) {
		return nil, err
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(r1)), packetSize), nil
}

func (session *Session) SendPacket(packet []byte) {
	syscall.SyscallN(procWintunSendPacket.Addr(), session.handle, uintptr(unsafe.Pointer(&packet[0])), 0) //nolint:errcheck
}
