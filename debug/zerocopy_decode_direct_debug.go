package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"reflect"
)

var ifaceName string
var filter string

func init() {
	flag.StringVar(&ifaceName, "i", "enp0s3", "Interface name")
	flag.StringVar(&filter, "bpf", "", "BPF filter")
	flag.Parse()
}

type MyDecodeFeedback struct {
	Truncated bool
}

func (df *MyDecodeFeedback) SetTruncated() {
	df.Truncated = true
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("must run as root")
		os.Exit(0)
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("failed to OpenLive by pcap, err: %s\n", err.Error())
		os.Exit(0)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Printf("failed to set BPF filter, err: %s\n", err.Error())
		os.Exit(0)
	}

	defer handle.Close()

	var eth layers.Ethernet
	var linuxSsl layers.LinuxSLL
	dlm := gopacket.DecodingLayerMap(make(map[gopacket.LayerType]gopacket.DecodingLayer))
	dlm.Put(&eth)
	dlm.Put(&linuxSsl)

	var firstLayer gopacket.LayerType
	var firstDec gopacket.DecodingLayer
	for k, v := range dlm {
		f1 := layers.LinkTypeMetadata[handle.LinkType()].DecodeWith
		f2 := gopacket.DecodersByLayerName[k.String()]

		if reflect.ValueOf(f1) == reflect.ValueOf(f2) {
			firstLayer = k
			firstDec = v
			break
		}
	}

	if firstDec == nil {
		fmt.Println("failed to find first decode layer")
		os.Exit(0)
	}

	decoded := make([]gopacket.LayerType, 0, 4)
	df := MyDecodeFeedback{}
	for i := 0; i < 100; i++ {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			fmt.Printf("error getting packet: %v", err)
			continue
		}

		layer := firstLayer
		decoder := firstDec
		decoded = decoded[:0]
		for {
			err := decoder.DecodeFromBytes(data, &df)
			if err != nil {
				break
			}
			decoded = append(decoded, layer)
			layer = decoder.NextLayerType()
			if data = decoder.LayerPayload(); len(data) == 0 {
				break
			}
		}

		fmt.Printf("decoded the following layers: %v", decoded)
	}
}
