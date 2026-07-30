package tun

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	siteA = netip.MustParsePrefix("10.81.0.0/24")
	siteB = netip.MustParsePrefix("10.82.0.0/24")
)

func validPacket() []byte {
	p := make([]byte, 20)
	p[0], p[8], p[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 81, 0, 11})
	copy(p[16:20], []byte{10, 82, 0, 22})
	binary.BigEndian.PutUint16(p[10:12], checksum(p))
	return p
}

func TestAuthorizeIPv4(t *testing.T) {
	p := append(validPacket(), 0xde, 0xad)
	want := append([]byte(nil), p...)
	total, err := AuthorizeIPv4(p, siteA, siteB)
	if err != nil {
		t.Fatal(err)
	}
	if total != 20 {
		t.Fatalf("canonical length=%d, want 20", total)
	}
	if !bytes.Equal(p, want) || p[8] != 64 || checksum(p[:total]) != 0 {
		t.Fatal("policy validation mutated TTL, checksum, or payload")
	}
}

func TestAuthorizeIPv4RejectsInvalidPackets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "bad checksum", mutate: func(p []byte) { p[10] ^= 1 }},
		{name: "wrong source", mutate: func(p []byte) { p[12] = 99; repairChecksum(p) }},
		{name: "wrong destination", mutate: func(p []byte) { p[16] = 99; repairChecksum(p) }},
		{name: "bad total", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 19); repairChecksum(p) }},
		{name: "truncated", mutate: func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 21); repairChecksum(p) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPacket()
			tt.mutate(p)
			if _, err := AuthorizeIPv4(p, siteA, siteB); err == nil {
				t.Fatal("invalid packet accepted")
			}
		})
	}
}

func TestAuthorizeIPv4LeavesLowTTLForKernelRoutingSemantics(t *testing.T) {
	p := validPacket()
	p[8] = 1
	repairChecksum(p)
	want := append([]byte(nil), p...)
	if total, err := AuthorizeIPv4(p, siteA, siteB); err != nil || total != len(p) {
		t.Fatalf("valid low-TTL packet rejected before kernel routing: total=%d err=%v", total, err)
	}
	if !bytes.Equal(p, want) {
		t.Fatal("low-TTL packet was mutated in userspace")
	}
}

func repairChecksum(p []byte) {
	p[10], p[11] = 0, 0
	headerLen := int(p[0]&0x0f) * 4
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:headerLen]))
}

func FuzzAuthorizeIPv4(f *testing.F) {
	f.Add(validPacket())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 2048 {
			t.Skip()
		}
		_, _ = AuthorizeIPv4(append([]byte(nil), packet...), siteA, siteB)
	})
}
