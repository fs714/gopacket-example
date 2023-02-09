package pktparser

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ErrUnsupportedLayerType = errors.New("unsupported layer type")

type DecodeFeedback struct {
	Truncated bool
}

func (f *DecodeFeedback) SetTruncated() {
	f.Truncated = true
}

type DecodingLayerSparse []gopacket.DecodingLayer

func (dl DecodingLayerSparse) Put(d gopacket.DecodingLayer) gopacket.DecodingLayerContainer {
	maxLayerType := gopacket.LayerType(len(dl) - 1)
	for _, typ := range d.CanDecode().LayerTypes() {
		if typ > maxLayerType {
			maxLayerType = typ
		}
	}

	if extra := maxLayerType - gopacket.LayerType(len(dl)) + 1; extra > 0 {
		dl = append(dl, make([]gopacket.DecodingLayer, extra)...)
	}

	for _, typ := range d.CanDecode().LayerTypes() {
		dl[typ] = d
	}
	return dl
}

func (dl DecodingLayerSparse) LayersDecoder(first gopacket.LayerType, df gopacket.DecodeFeedback) gopacket.DecodingLayerFunc {
	firstDec, ok := dl.Decoder(first)
	if !ok {
		return func([]byte, *[]gopacket.LayerType) (gopacket.LayerType, error) {
			return first, nil
		}
	}

	return func(data []byte, decoded *[]gopacket.LayerType) (gopacket.LayerType, error) {
		*decoded = (*decoded)[:0] // Truncated decoded layers.
		layerType := first
		decoder := firstDec
		for {
			if err := decoder.DecodeFromBytes(data, df); err != nil {
				return gopacket.LayerTypeZero, err
			}
			*decoded = append(*decoded, layerType)

			if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
				return gopacket.LayerTypeZero, nil
			}

			nextLayerType := decoder.NextLayerType()

			if layerType == layers.LayerTypeIPv4 && nextLayerType != layers.LayerTypeTCP && nextLayerType != layers.LayerTypeUDP {
				return nextLayerType, nil
			}

			layerType = nextLayerType
			if data = decoder.LayerPayload(); len(data) == 0 {
				break
			}

			if decoder, ok = dl.Decoder(layerType); !ok {
				return layerType, ErrUnsupportedLayerType
			}
		}

		return gopacket.LayerTypeZero, nil
	}
}

func (dl DecodingLayerSparse) Decoder(typ gopacket.LayerType) (gopacket.DecodingLayer, bool) {
	if int64(typ) < int64(len(dl)) {
		decoder := dl[typ]
		return decoder, decoder != nil
	}
	return nil, false
}
