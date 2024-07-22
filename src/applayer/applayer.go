package applayer

import "github.com/google/gopacket"

type appLayer struct {
}

func FetchAppLayer(packet gopacket.Packet) gopacket.Packet {
	if packet.ApplicationLayer() != nil {
		packet.Dump()
	}

	return packet
}
