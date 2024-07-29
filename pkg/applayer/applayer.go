package applayer

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
)

type appLayer struct {
	Payload []byte
}

// ParseAppLayer extracts app layer information from the packet and populates the appLayer struct
func ParseAppLayer(packet gopacket.Packet) (*appLayer, error) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		return &appLayer{Payload: applicationLayer.Payload()}, nil
	}

	return nil, errors.New("error parsing L7 layer")
}

// Info returns a string with formatted information about the L7 layer info
func (a *appLayer) Info() string {
	if a == nil {
		return "Application Layer is empty"
	}
	return fmt.Sprintf(`
======== LAYER 7 (APP) =========
[TOTAL PAYLOAD]: %v bytes
[PAYLOAD]: %s`,
		len(a.Payload),
		a.Payload,
	)

}
