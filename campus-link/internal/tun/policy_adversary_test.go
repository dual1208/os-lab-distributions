package tun

import (
	"encoding/binary"
	"testing"
)

func TestAuthorizeIPv4RejectsSourceRoutingOptions(t *testing.T) {
	for _, optionType := range []byte{131, 137} { // LSRR and SSRR.
		packet := make([]byte, 28)
		packet[0], packet[8], packet[9] = 0x47, 64, 1
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], []byte{10, 81, 0, 11})
		copy(packet[16:20], []byte{10, 82, 0, 22})
		packet[20], packet[21], packet[22] = optionType, 7, 4
		copy(packet[23:27], []byte{192, 0, 2, 99})
		packet[27] = 0 // End-of-options padding.
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet))
		if _, err := AuthorizeIPv4(packet, siteA, siteB); err == nil {
			t.Fatalf("IPv4 source-route option %d bypassed the fixed-prefix policy", optionType)
		}
	}
}

func fragmentPacket(field uint16, payloadLen int) []byte {
	packet := make([]byte, 20+payloadLen)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], field)
	copy(packet[12:16], []byte{10, 81, 0, 11})
	copy(packet[16:20], []byte{10, 82, 0, 22})
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	return packet
}

func TestAuthorizeIPv4RejectsMalformedFragmentFormsAndReservedFlag(t *testing.T) {
	for name, packet := range map[string][]byte{
		"reserved":        fragmentPacket(0x8000, 0),
		"df-more":         fragmentPacket(0x6000, 8),
		"df-offset":       fragmentPacket(0x4001, 8),
		"empty-more":      fragmentPacket(0x2000, 0),
		"empty-offset":    fragmentPacket(0x0001, 0),
		"unaligned-more":  fragmentPacket(0x2000, 7),
		"extent-overflow": fragmentPacket(0x1fff, 8),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := AuthorizeIPv4(packet, siteA, siteB); err == nil {
				t.Fatal("malformed fragment bypassed policy")
			}
		})
	}
}

func TestAuthorizeIPv4AllowsAuthenticatedKernelFragments(t *testing.T) {
	for name, packet := range map[string][]byte{
		"first":  fragmentPacket(0x2000, 16),
		"middle": fragmentPacket(0x2002, 16),
		"final":  fragmentPacket(0x0004, 7),
	} {
		t.Run(name, func(t *testing.T) {
			if total, err := AuthorizeIPv4(packet, siteA, siteB); err != nil || total != len(packet) {
				t.Fatalf("valid kernel fragment rejected: total=%d err=%v", total, err)
			}
		})
	}
}

func TestAuthorizeIPv4AllowsCanonicalUnfragmentedDFPacket(t *testing.T) {
	packet := make([]byte, 20)
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	copy(packet[12:16], []byte{10, 81, 0, 11})
	copy(packet[16:20], []byte{10, 82, 0, 22})
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet))
	if total, err := AuthorizeIPv4(packet, siteA, siteB); err != nil || total != len(packet) {
		t.Fatalf("canonical DF packet rejected: total=%d err=%v", total, err)
	}
}
