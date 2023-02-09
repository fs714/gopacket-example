package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/fs714/gopacket-example/gopacket_extend/example02/pktparser"
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
	tcp := &layers.TCP{}
	udp := &layers.UDP{}

	decodingLayerList := []gopacket.DecodingLayer{eth, linuxSll, dot1q, ip4, tcp, udp}

	dls := pktparser.NewDecodingLayerSparse()
	dlc := gopacket.DecodingLayerContainer(dls)
	for _, l := range decodingLayerList {
		dlc = dlc.Put(l)
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
	var ts string
	var protocol string
	var srcAddr, dstAddr string
	var srcPort, dstPort uint16
	for {
		data, ci, err = handle.ZeroCopyReadPacketData()
		if err != nil {
			fmt.Printf("error getting packet: %s\n", err.Error())
			continue
		}

		lt, err := decoder(data, &decoded)
		if err != nil {
			if errors.Is(err, pktparser.ErrUnsupportedLayerType) {
				fmt.Printf("unsupported layer type: %s\n", lt.String())
			} else {
				fmt.Printf("failed to decode layer %s with err: %v\n", lt.String(), err)
			}

			continue
		}

		detectedLen := len(decoded)
		if decoded[detectedLen-1] == layers.LayerTypeTCP {
			ts = ci.Timestamp.Format(time.RFC3339Nano)
			protocol = "tcp"
			srcAddr = ip4.SrcIP.String()
			dstAddr = ip4.DstIP.String()
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		} else if decoded[detectedLen-1] == layers.LayerTypeUDP {
			ts = ci.Timestamp.Format(time.RFC3339Nano)
			protocol = "udp"
			srcAddr = ip4.SrcIP.String()
			dstAddr = ip4.DstIP.String()
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
		} else if decoded[detectedLen-1] == layers.LayerTypeIPv4 {
			ts = ci.Timestamp.Format(time.RFC3339Nano)
			protocol = lt.String()
			srcAddr = ip4.SrcIP.String()
			dstAddr = ip4.DstIP.String()
			srcPort = 0
			dstPort = 0
		} else {
			fmt.Println("no ipv4 layer detected")
			continue
		}

		fmt.Printf("%-28s %-8s %-16s %-16s %-6d %-6d\n", ts, protocol, srcAddr, dstAddr, srcPort, dstPort)
	}
}
