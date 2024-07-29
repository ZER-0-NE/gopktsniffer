package ippacket

import (
	"errors"
	"fmt"
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

// ParseIv4PPacket extracts IPv4 information from the packet and populates the IPv4Packet struct
func ParseIv4PPacket(packet gopacket.Packet) (*IPv4Packet, error) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ipv4 := ipLayer.(*layers.IPv4)
		return &IPv4Packet{
			IHL:     ipv4.IHL,
			SrcIp:   ipv4.SrcIP,
			DstIp:   ipv4.DstIP,
			Version: ipv4.Version,
			TTL:     ipv4.TTL,
			V4Flags: ipv4.Flags,
			Len:     ipv4.Length,
		}, nil
	}
	return nil, errors.New("failed to parse IPv4 layer from packet")
}

// Info returns a string with formatted information about the IP packet
func (ip *IPv4Packet) Info() string {
	if ip == nil {
		return "IPv4Packet is nil"
	}

	return fmt.Sprintf(`


======== LAYER 3 (IP) =========
[HEADER LENGTH]: %v bytes
[Total Length]: %v bytes
[IP Packet Version]: %v
[Source IP]: %v
[Destination IP]: %v
[TTL]: %v
[FLAGS]: %v`,
		ip.IHL*4, // IHL is in 32-bit words, so multiply by 4 to get bytes
		ip.Len,
		ip.Version,
		ip.SrcIp,
		ip.DstIp,
		ip.TTL,
		ip.V4Flags,
	)
}
