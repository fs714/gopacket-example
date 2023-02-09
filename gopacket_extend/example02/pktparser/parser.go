package pktparser

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
)

var ErrUnsupportedLayerType = errors.New("unsupported layer type")
var ErrIPv4DefragFailed = errors.New("ipv4 defrag failed")

type DecodeFeedback struct {
	Truncated bool
}

func (f *DecodeFeedback) SetTruncated() {
	f.Truncated = true
}

type DecodingLayerSparse struct {
	Layers    []gopacket.DecodingLayer
	defragger *ip4defrag.IPv4Defragmenter
}

func NewDecodingLayerSparse() *DecodingLayerSparse {
	return &DecodingLayerSparse{
		Layers:    make([]gopacket.DecodingLayer, 0),
		defragger: ip4defrag.NewIPv4Defragmenter(),
	}
}

func (dl *DecodingLayerSparse) Put(d gopacket.DecodingLayer) gopacket.DecodingLayerContainer {
	maxLayerType := gopacket.LayerType(len(dl.Layers) - 1)
	for _, typ := range d.CanDecode().LayerTypes() {
		if typ > maxLayerType {
			maxLayerType = typ
		}
	}

	if extra := maxLayerType - gopacket.LayerType(len(dl.Layers)) + 1; extra > 0 {
		dl.Layers = append(dl.Layers, make([]gopacket.DecodingLayer, extra)...)
	}

	for _, typ := range d.CanDecode().LayerTypes() {
		dl.Layers[typ] = d
	}
	return dl
}

func (dl *DecodingLayerSparse) LayersDecoder(first gopacket.LayerType, df gopacket.DecodeFeedback) gopacket.DecodingLayerFunc {
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
				return gopacket.LayerTypeDecodeFailure, err
			}
			*decoded = append(*decoded, layerType)

			if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
				return gopacket.LayerTypePayload, nil
			}

			nextLayerType := decoder.NextLayerType()

			if layerType == layers.LayerTypeIPv4 {
				if nextLayerType == gopacket.LayerTypeFragment {
					dec, _ := dl.Decoder(layers.LayerTypeIPv4)
					ip4 := dec.(*layers.IPv4)
					l := ip4.Length

					newip4, err := dl.defragger.DefragIPv4(ip4)
					if err != nil {
						return gopacket.LayerTypeDecodeFailure, err
					} else if newip4 == nil {
						return gopacket.LayerTypeFragment, nil
					}

					if newip4.Length != l {
						ip4 = newip4
						return newip4.NextLayerType(), nil
					} else {
						return gopacket.LayerTypeDecodeFailure, ErrIPv4DefragFailed
					}
				}

				if nextLayerType != layers.LayerTypeTCP && nextLayerType != layers.LayerTypeUDP {
					return nextLayerType, nil
				}
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

func (dl *DecodingLayerSparse) Decoder(typ gopacket.LayerType) (gopacket.DecodingLayer, bool) {
	if int64(typ) < int64(len(dl.Layers)) {
		decoder := dl.Layers[typ]
		return decoder, decoder != nil
	}
	return nil, false
}
