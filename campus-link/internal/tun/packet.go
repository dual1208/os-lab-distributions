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

// AuthorizeIPv4 validates policy and the IPv4 header, decrements TTL, updates
// the checksum, and returns the canonical IP length. Callers must discard any
// bytes beyond that length before forwarding.
func AuthorizeIPv4(packet []byte, source, destination netip.Prefix) (int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, errShortPacket
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return 0, errShortPacket
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
	if packet[8] <= 1 {
		return 0, errors.New("TTL expired")
	}
	packet[8]--
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLen]))
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
