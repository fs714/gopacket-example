package pktlayers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPSecAH struct {
	layers.BaseLayer
	NextHeader         layers.IPProtocol
	HeaderLength       uint8
	ActualLength       int
	Reserved           uint16
	SPI, Seq           uint32
	AuthenticationData []byte
}

func (i *IPSecAH) LayerType() gopacket.LayerType { return layers.LayerTypeIPSecAH }

func (i *IPSecAH) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 12 {
		df.SetTruncated()
		return errors.New("IPSec AH packet less than 12 bytes")
	}

	i.NextHeader = layers.IPProtocol(data[0])
	i.HeaderLength = data[1]
	i.Reserved = binary.BigEndian.Uint16(data[2:4])
	i.SPI = binary.BigEndian.Uint32(data[4:8])
	i.Seq = binary.BigEndian.Uint32(data[8:12])
	i.ActualLength = (int(i.HeaderLength) + 2) * 4
	if len(data) < i.ActualLength {
		df.SetTruncated()
		return errors.New("truncated AH packet < ActualLength")
	}
	i.AuthenticationData = data[12:i.ActualLength]
	i.Contents = data[:i.ActualLength]
	i.Payload = data[i.ActualLength:]

	return nil
}

func (i *IPSecAH) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeIPSecAH
}

func (i *IPSecAH) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
