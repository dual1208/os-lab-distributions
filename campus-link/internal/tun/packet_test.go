package tun

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestAuthorizeIPv4(t *testing.T) {
	p := make([]byte, 20)
	p[0], p[8], p[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 81, 0, 10})
	copy(p[16:20], []byte{10, 82, 0, 10})
	if err := AuthorizeIPv4(p, netip.MustParsePrefix("10.81.0.0/24"), netip.MustParsePrefix("10.82.0.0/24")); err != nil {
		t.Fatal(err)
	}
	if p[8] != 63 || checksum(p) != 0 {
		t.Fatal("TTL or checksum was not updated")
	}
	copy(p[12:16], []byte{10, 99, 0, 1})
	if err := AuthorizeIPv4(p, netip.MustParsePrefix("10.81.0.0/24"), netip.MustParsePrefix("10.82.0.0/24")); err == nil {
		t.Fatal("unauthorized source accepted")
	}
}
