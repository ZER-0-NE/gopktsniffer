package phylayer

import (
	"fmt"
	"github.com/google/gopacket"
)

type phyLayer struct {
	data []byte
}

func ParsePhysicalLayer(packet gopacket.Packet) (*phyLayer, error) {
	return &phyLayer{
		data: packet.Data(),
	}, nil
}

// Info prints information about the physical layer (Layer 1)
func (p *phyLayer) Info() string {
	return fmt.Sprintf(`


======== LAYER 1 (Physical/Over the Wire) =========
[BYTES OVER WIRE]: %v
[TOTAL PACKET BYTES]: %v bytes`,
		p.data,
		len(p.data),
	)

}
