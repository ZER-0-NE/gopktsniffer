package tcpseg

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopacketsniffer/pkg/ippacket"
	"strings"
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
func ParseTcpSegment(packet gopacket.Packet) (*TCPSegment, error) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return &TCPSegment{
			TCPHeader:  parseTCPHeader(tcp),
			Flags:      parseTCPFlags(tcp),
			Options:    tcp.Options,
			Padding:    tcp.Padding,
			TCPPayload: tcp.Payload,
		}, nil
	}
	return nil, errors.New("error parsing TCP layer from packet")
}

func (t *TCPSegment) tcpTupleInfo(ip *ippacket.IPv4Packet) string {
	return fmt.Sprintf("\n%v:%v > %v:%v\n", ip.SrcIp, t.TCPHeader.SrcPort, ip.DstIp, t.TCPHeader.DstPort)
}

func (t *TCPSegment) tcpFlagInfo(flag string) string {
	return fmt.Sprintf("\n[%s] \n[Seq]:%v", flag, t.TCPHeader.Seq)
}

// Info prints information about the TCP layer (Layer 4)
func (t *TCPSegment) Info(ip *ippacket.IPv4Packet) string {

	if t == nil || ip.Len == 0 {
		return "Missing TCP/IPv4 layer packet"
	}
	var sb strings.Builder

	fmt.Fprintf(&sb, "\n\n======== LAYER 4 (TCP) =========\n")
	fmt.Fprintf(&sb, "[SEGMENT LENGTH]: %v\n", len(t.TCPPayload))
	fmt.Fprintf(&sb, "[HEADER LENGTH(DATA OFFSET)]: %v\n", t.TCPHeader.DataOffset*4) // DataOffset is in 32-bit words
	if mss := t.GetOption(layers.TCPOptionKindMSS); mss != nil {
		fmt.Fprintf(&sb, "[MSS]: %v\n", mss)
	}
	fmt.Fprintf(&sb, "[WINDOW SIZE]: %v\n", t.TCPHeader.Window)
	fmt.Fprintf(&sb, "[CWR]: %v\n", t.Flags.CWR)

	// Print information for different TCP flags
	if t.Flags.SYN {
		fmt.Fprintf(&sb, t.tcpFlagInfo("SYN"))
		fmt.Fprintf(&sb, t.tcpTupleInfo(ip))
	}
	if t.Flags.SYN && t.Flags.ACK {
		fmt.Fprintf(&sb, t.tcpFlagInfo("SYN/ACK"))
		fmt.Fprintf(&sb, t.tcpTupleInfo(ip))
	}
	if t.Flags.ACK {
		fmt.Fprintf(&sb, "[ACK NUM]: %v\n", t.TCPHeader.Ack)
		fmt.Fprintf(&sb, t.tcpFlagInfo("ACK"))
		fmt.Fprintf(&sb, t.tcpTupleInfo(ip))
	}
	if t.Flags.FIN {
		fmt.Fprintf(&sb, t.tcpFlagInfo("FIN"))
		fmt.Fprintf(&sb, t.tcpTupleInfo(ip))
		fmt.Fprintf(&sb, "Closing connection\n")
	}
	if t.Flags.RST {
		fmt.Fprintf(&sb, t.tcpFlagInfo("RST"))
		fmt.Fprintf(&sb, t.tcpTupleInfo(ip))
		fmt.Fprintf(&sb, "[PORT CLOSE]: %v\n", t.TCPHeader.SrcPort)
	}

	return sb.String()
}
