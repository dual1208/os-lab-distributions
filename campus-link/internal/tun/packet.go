package tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	errShortPacket = errors.New("short IPv4 packet")
	errPolicy      = errors.New("packet outside authorized prefixes")
	errChecksum    = errors.New("invalid IPv4 header checksum")
)

// AuthorizeIPv4 validates policy and the IPv4 header without mutating the
// packet, and returns the canonical IP length. The kernels routing into and
// out of the TUN own TTL/ICMP semantics. Callers must discard bytes beyond the
// canonical length before forwarding.
func AuthorizeIPv4(packet []byte, source, destination netip.Prefix) (int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, errShortPacket
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return 0, errShortPacket
	}
	if headerLen != 20 {
		return 0, errPolicy
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < headerLen || total > len(packet) {
		return 0, errShortPacket
	}
	if checksum(packet[:headerLen]) != 0 {
		return 0, errChecksum
	}
	src, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return 0, errShortPacket
	}
	dst, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return 0, errShortPacket
	}
	if !source.Contains(src.Unmap()) || !destination.Contains(dst.Unmap()) {
		return 0, errPolicy
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	const (
		reservedFlag  = uint16(0x8000)
		dontFragment  = uint16(0x4000)
		moreFragments = uint16(0x2000)
		offsetMask    = uint16(0x1fff)
	)
	offset := int(fragment&offsetMask) * 8
	payloadLen := total - headerLen
	fragmented := fragment&moreFragments != 0 || offset != 0
	if fragment&reservedFlag != 0 || (fragmented && fragment&dontFragment != 0) {
		return 0, errPolicy
	}
	if fragmented && payloadLen == 0 {
		return 0, errPolicy
	}
	if fragment&moreFragments != 0 && payloadLen%8 != 0 {
		return 0, errPolicy
	}
	if offset+payloadLen > 65535-headerLen {
		return 0, errPolicy
	}
	return total, nil
}

func checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
