package iphlpapi

/*
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
*/
import "C"

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                        = windows.MustLoadDLL("iphlpapi.dll")
	initializeUnicastIpAddressEntry = iphlpapi.MustFindProc("InitializeUnicastIpAddressEntry")
	createUnicastIpAddressEntry     = iphlpapi.MustFindProc("CreateUnicastIpAddressEntry")
)

func InitializeUnicastIpAddressEntry() (row C.MIB_UNICASTIPADDRESS_ROW) {
	_, _, _ = initializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	return
}

func CreateUnicastIpAddressEntry(row *C.MIB_UNICASTIPADDRESS_ROW) (err error) {
	ret, _, _ := createUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	err = windows.Errno(ret)
	if err == windows.ERROR_SUCCESS {
		err = nil
	}
	return
}

func SetAdapterIPv4(luid uint64, ip []byte, subnet int) (err error) {
	row := InitializeUnicastIpAddressEntry()
	ipv4 := (*C.struct_sockaddr_in)(unsafe.Pointer(&row.Address))
	ipv4.sin_family = C.AF_INET
	copy(ipv4.sin_addr.S_un[:], ip)
	row.OnLinkPrefixLength = C.uchar(subnet)
	row.DadState = C.IpDadStatePreferred
	*(*uint64)(unsafe.Pointer(&row.InterfaceLuid)) = luid
	err = CreateUnicastIpAddressEntry(&row)
	return
}
