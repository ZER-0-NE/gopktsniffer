package tls

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TLSHeader struct {
	ContentType layers.TLSType
	Version     layers.TLSVersion
	Length      uint16
	Payload     []byte
}

func (t *TLSHeader) handleTLS(packet gopacket.Packet) *TLSHeader {
	if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
		tls := tlsLayer.(*layers.TLS)
		t.Payload = tls.Payload()
		t.Version = layers.TLSVersion(binary.BigEndian.Uint16(t.Payload[1:3]))
		t.ContentType = layers.TLSType(t.Payload[0])
	}
	return t
}

func TLS(packet gopacket.Packet) *TLSHeader {
	tls := TLSHeader{}
	return tls.handleTLS(packet)
}
