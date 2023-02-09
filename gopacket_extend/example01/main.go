package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/fs714/gopacket-example/gopacket_extend/example01/pktparser"
	"github.com/fs714/gopacket-example/gopacket_extend/example01/pktparser/pktlayers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var ifaceName string
	flag.StringVar(&ifaceName, "i", "", "interface name")
	flag.Parse()

	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("failed to open live interface %s with err: %s\n", ifaceName, err.Error())
		return
	}

	err = handle.SetBPFFilter("")
	if err != nil {
		fmt.Printf("failed to set BPF filter with err: %s\n", err.Error())
		return
	}

	defer handle.Close()

	eth := &layers.Ethernet{}
	linuxSll := &layers.LinuxSLL{}
	dot1q := &layers.Dot1Q{}
	ip4 := &layers.IPv4{}
	icmpv4 := &layers.ICMPv4{}
	tcp := &layers.TCP{}
	udp := &layers.UDP{}
	ipsecAH := &pktlayers.IPSecAH{}
	ipsecESP := &pktlayers.IPSecESP{}
	payload := &gopacket.Payload{}

	decodingLayerList := []gopacket.DecodingLayer{eth, linuxSll, dot1q, ip4, icmpv4, tcp, udp, ipsecAH, ipsecESP, payload}

	dls := &pktparser.DecodingLayerSparse{}
	dlc := gopacket.DecodingLayerContainer(dls)
	for _, l := range decodingLayerList {
		dlc.Put(l)
	}

	var firstLayer gopacket.LayerType
	if handle.LinkType().String() == "Raw" {
		firstLayer = layers.LayerTypeIPv4
	} else {
		firstLayer = dls.GetFirstLayerType(handle.LinkType())
	}

	df := &pktparser.DecodeFeedback{}
	decoder := dlc.LayersDecoder(firstLayer, df)
	decoded := make([]gopacket.LayerType, 0, len(decodingLayerList))

	var data []byte
	var ci gopacket.CaptureInfo
	for {
		data, ci, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			fmt.Printf("error getting packet: %s\n", err.Error())
			continue
		}

		lt, err := decoder(data, &decoded)
		if err != nil {
			fmt.Printf("failed to decode layer %s with err: %v\n", lt.String(), err)
			continue
		}

		if lt != gopacket.LayerTypeZero {
			fmt.Printf("unsupported layer type: %s\n", lt.String())
		}

		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeICMPv4:
				ts := ci.Timestamp.Format(time.RFC3339Nano)
				srcAddr := ip4.SrcIP.String()
				dstAddr := ip4.DstIP.String()
				id := icmpv4.Id
				seq := icmpv4.Seq
				typeCode := icmpv4.TypeCode
				fmt.Printf("%-28s icmp  %-16s %-16s %-6d %-4d %-16s\n", ts, srcAddr, dstAddr, id, seq, typeCode.String())
			case layers.LayerTypeTCP:
				ts := ci.Timestamp.Format(time.RFC3339Nano)
				srcAddr := ip4.SrcIP.String()
				dstAddr := ip4.DstIP.String()
				srcPort := tcp.SrcPort
				dstPort := tcp.DstPort
				fmt.Printf("%-28s tcp  %-16s %-16s %-6d %-6d\n", ts, srcAddr, dstAddr, srcPort, dstPort)
			case layers.LayerTypeIPSecESP:
				ts := ci.Timestamp.Format(time.RFC3339Nano)
				srcAddr := ip4.SrcIP.String()
				dstAddr := ip4.DstIP.String()
				spi := ipsecESP.SPI
				seq := ipsecESP.Seq
				fmt.Printf("%-28s esp  %-16s %-16s %-6d %-6d\n", ts, srcAddr, dstAddr, spi, seq)
			}
		}
	}
}
