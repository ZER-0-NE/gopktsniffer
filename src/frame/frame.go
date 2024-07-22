package frame

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
)

type L2Frame struct {
	// The source address indicates the MAC address of the network interface which sent the frame. This enables other machines on the network to
	// identify and reply to messages received from this machine.
	SrcMac net.HardwareAddr

	// The destination address indicates the MAC address of the network interface which should receive a given frame.
	// In some cases, this may be the Ethernet broadcast address: ff:ff:ff:ff:ff:ff. Some protocols, such as ARP, send frames with a broadcast
	// destination in order to send a message to all machines on a given network segment. When a network switch receives a frame with the broadcast
	// address, it duplicates the frame to each port attached to the switch.
	DstMac net.HardwareAddr

	// The EtherType indicates which protocol is encapsulated in the payload portion of
	// a given frame. Some typical examples include Layer 3 protocols such as ARP, IPv4, and IPv6.
	// The payload of an Ethernet frame can contain anywhere from 46 to 1500 (or more!) bytes of data, depending on how the machines
	// on a Layer 2 network segment are configured. The payload can carry arbitrary data, including the headers for Layer 3 and
	// above protocols (which may even encapsulate traffic at higher layers).
	EtherType layers.EthernetType

	FrameLen uint16

	// Max Transmission Unit
	MTU int
}

// handleL2Frames extracts L2 frame information from a gopacket.Packet
func (f *L2Frame) handleL2Frames(packet gopacket.Packet) *L2Frame {
	if l2Frame := packet.Layer(layers.LayerTypeEthernet); l2Frame != nil {
		frame := l2Frame.(*layers.Ethernet)
		f.SrcMac = frame.SrcMAC
		f.DstMac = frame.DstMAC
		f.EtherType = frame.EthernetType

		intf, err := net.InterfaceByName("en0")
		if err != nil {
			log.Fatalf("failed to open interface: %v", err)
		}
		f.MTU = intf.MTU
		f.FrameLen = frame.Length
	}
	return f
}

// Frames return a L2Frame from a gopacket.Packet
func Frames(packet gopacket.Packet) *L2Frame {
	f := &L2Frame{}

	return f.handleL2Frames(packet)
}
