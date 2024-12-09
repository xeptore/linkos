//go:build windows && amd64

package iphlpapi

/*
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                        = windows.MustLoadDLL("iphlpapi.dll")
	initializeUnicastIPAddressEntry = iphlpapi.MustFindProc("InitializeUnicastIpAddressEntry")
	createUnicastIPAddressEntry     = iphlpapi.MustFindProc("CreateUnicastIpAddressEntry")
)

func InitializeUnicastIPAddressEntry() (row C.MIB_UNICASTIPADDRESS_ROW) {
	_, _, _ = initializeUnicastIPAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	return
}

func CreateUnicastIPAddressEntry(row *C.MIB_UNICASTIPADDRESS_ROW) error {
	ret, _, _ := createUnicastIPAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if err := windows.Errno(ret); !errors.Is(err, windows.ERROR_SUCCESS) {
		return err
	}
	return nil
}

func SetAdapterIPv4(luid uint64, ip []byte, subnet int) (err error) {
	row := InitializeUnicastIPAddressEntry()
	ipv4 := (*C.struct_sockaddr_in)(unsafe.Pointer(&row.Address))
	ipv4.sin_family = C.AF_INET
	copy(ipv4.sin_addr.S_un[:], ip)
	row.OnLinkPrefixLength = C.uchar(subnet)
	row.DadState = C.IpDadStatePreferred
	*(*uint64)(unsafe.Pointer(&row.InterfaceLuid)) = luid
	err = CreateUnicastIPAddressEntry(&row)
	return
}
