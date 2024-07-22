package ip_packet

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

type IPv4Packet struct {
	// Internet Header Length
	IHL     uint8
	SrcIp   net.IP
	DstIp   net.IP
	Version uint8
	TTL     uint8

	// DF - Don't fragment
	//  MF - More Fragment
	// Evil - Evil bit set
	V4Flags layers.IPv4Flag

	// this 16-bit field indicates the entire size of the IP packet (header and data) in bytes. The minimum size is 20 bytes
	// (if you have no data) and the maximum size is 65,535 bytes, that’s the highest value you can create with 16 bits.
	Len uint16
}

// handleIPPacket extracts IPv4 information from the packet and populates the IPv4Packet struct
func (ip *IPv4Packet) handleIPPacket(packet gopacket.Packet) *IPv4Packet {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ipv4 := ipLayer.(*layers.IPv4)
		ip.SrcIp = ipv4.SrcIP
		ip.DstIp = ipv4.DstIP
		ip.Version = ipv4.Version
		ip.TTL = ipv4.TTL
		ip.V4Flags = ipv4.Flags
		ip.Len = ipv4.Length
		ip.IHL = ipv4.IHL
	}
	return ip
}

// IPPacket creates and returns an IPv4Packet from a gopacket.Packet
func IPPacket(packet gopacket.Packet) *IPv4Packet {
	ip := &IPv4Packet{}

	return ip.handleIPPacket(packet)
}
