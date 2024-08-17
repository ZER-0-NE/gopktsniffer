package frame

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopacketsniffer/pkg/config"
	"log"
	"net"
	//const "gopacketsniffer/pkg/const"
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

// ParseL2Frames extracts L2 frame information from a gopacket.Packet
func ParseL2Frames(packet gopacket.Packet) (*L2Frame, error) {
	// for using global flags
	config.Init()

	if l2Frame := packet.Layer(layers.LayerTypeEthernet); l2Frame != nil {
		frame := l2Frame.(*layers.Ethernet)

		intf, err := net.InterfaceByName(*config.IntfName)
		if err != nil {
			log.Fatalf("failed to open interface: %v", err)
		}

		return &L2Frame{
			SrcMac:    frame.SrcMAC,
			DstMac:    frame.DstMAC,
			EtherType: frame.EthernetType,
			FrameLen:  frame.Length,
			MTU:       intf.MTU,
		}, nil

	}
	return nil, errors.New("error parsing frame from packet")
}

// Info prints information about the data link layer (Layer 2)
func (f *L2Frame) Info() string {
	if f == nil {
		return "Frame is nil"
	}
	return fmt.Sprintf(`


======== LAYER 2 (Data Link) =========
[MTU]: %v bytes
EtherType: %v
L2 Frame: %v > %v
[FRAME LEN]: %v`,
		f.MTU,
		f.EtherType,
		f.SrcMac,
		f.DstMac,
		f.FrameLen,
	)
}
