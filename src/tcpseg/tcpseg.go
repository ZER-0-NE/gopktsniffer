package tcpseg

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TCPSegment represents a TCP segment with its header, flags, options, and payload
// TCPSegment header is 20 bytes and can go up to 60 bytes
type TCPSegment struct {
	TCPHeader  TCPHeader
	Flags      TCPFlags
	Options    []layers.TCPOption
	Padding    []byte
	TCPPayload []byte
}

// TCPHeader represents the fields in a TCP header
type TCPHeader struct {
	SrcPort, DstPort layers.TCPPort // 16 bit each
	Seq              uint32         // 32 bits - Sequence number
	Ack              uint32         // 32 bits - Acknowledgment number
	DataOffset       uint8          // 4 bits - Size of TCP header in 32-bit words
	Window           uint16         // 16 bits - Size of the receive window
	Checksum         uint16         // 16 bits - Error-checking of the header and data
	Urgent           uint16         // 16 bits - Urgent pointer
}

// TCPFlags represents the various flags in a TCP header
type TCPFlags struct {
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool // 1 bit each
}

// parseTCPHeader extracts TCP header information from the gopacket TCP layer
func parseTCPHeader(tcp *layers.TCP) TCPHeader {
	return TCPHeader{
		SrcPort:    tcp.SrcPort,
		DstPort:    tcp.DstPort,
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		DataOffset: tcp.DataOffset,
		Window:     tcp.Window,
		Checksum:   tcp.Checksum,
		Urgent:     tcp.Urgent,
	}
}

// parseTCPFlags extracts TCP flags from the gopacket TCP layer
func parseTCPFlags(tcp *layers.TCP) TCPFlags {
	return TCPFlags{
		FIN: tcp.FIN,
		SYN: tcp.SYN,
		RST: tcp.RST,
		PSH: tcp.PSH,
		ACK: tcp.ACK,
		URG: tcp.URG,
		ECE: tcp.ECE,
		CWR: tcp.CWR,
		NS:  tcp.NS,
	}
}

// GetOption retrieves a specific TCP option by kind
func (t *TCPSegment) GetOption(kind layers.TCPOptionKind) *layers.TCPOption {
	for _, option := range t.Options {
		if option.OptionType == kind {
			return &option
		}
	}
	return nil
}

// TcpSegment extracts TCP segment information from a gopacket.Packet
func TcpSegment(packet gopacket.Packet) *TCPSegment {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return &TCPSegment{
			TCPHeader:  parseTCPHeader(tcp),
			Flags:      parseTCPFlags(tcp),
			Options:    tcp.Options,
			Padding:    tcp.Padding,
			TCPPayload: tcp.Payload,
		}
	}
	return nil
}
