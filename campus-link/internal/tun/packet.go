package tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	errShortPacket = errors.New("short IPv4 packet")
	errPolicy      = errors.New("packet outside authorized prefixes")
)

func AuthorizeIPv4(packet []byte, source, destination netip.Prefix) error {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return errShortPacket
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return errShortPacket
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < headerLen || total > len(packet) {
		return errShortPacket
	}
	src, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return errShortPacket
	}
	dst, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return errShortPacket
	}
	if !source.Contains(src.Unmap()) || !destination.Contains(dst.Unmap()) {
		return errPolicy
	}
	if packet[8] <= 1 {
		return errors.New("TTL expired")
	}
	packet[8]--
	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLen]))
	return nil
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
