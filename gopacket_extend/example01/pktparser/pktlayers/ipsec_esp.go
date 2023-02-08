package pktlayers

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPSecESP struct {
	layers.BaseLayer
	SPI, Seq  uint32
	Encrypted []byte
}

func (i *IPSecESP) LayerType() gopacket.LayerType { return layers.LayerTypeIPSecESP }

func (i *IPSecESP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	i.SPI = binary.BigEndian.Uint32(data[:4])
	i.Seq = binary.BigEndian.Uint32(data[4:8])
	i.Encrypted = data[8:]
	i.Contents = data
	i.Payload = nil

	return nil
}

func (i *IPSecESP) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeIPSecESP
}

func (i *IPSecESP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
