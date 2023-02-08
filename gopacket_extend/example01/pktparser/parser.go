package pktparser

import "github.com/google/gopacket"

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
		typ := first
		decoder := firstDec
		for {
			if err := decoder.DecodeFromBytes(data, df); err != nil {
				return gopacket.LayerTypeZero, err
			}
			*decoded = append(*decoded, typ)
			typ = decoder.NextLayerType()
			if data = decoder.LayerPayload(); len(data) == 0 {
				break
			}
			if decoder, ok = dl.Decoder(typ); !ok {
				return typ, nil
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
