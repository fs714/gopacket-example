package main

import (
	"flag"
	"fmt"
	"time"

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
	ip4 := &layers.IPv4{}
	icmpv4 := &layers.ICMPv4{}
	tcp := &layers.TCP{}
	udp := &layers.UDP{}
	payload := &gopacket.Payload{}

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))
	dlc = dlc.Put(eth)
	dlc = dlc.Put(ip4)
	dlc = dlc.Put(icmpv4)
	dlc = dlc.Put(tcp)
	dlc = dlc.Put(udp)
	dlc = dlc.Put(payload)

	decoder := dlc.LayersDecoder(layers.LayerTypeEthernet, gopacket.NilDecodeFeedback)
	decoded := make([]gopacket.LayerType, 0, 20)

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
				id := icmpv4.Id
				seq := icmpv4.Seq
				typeCode := icmpv4.TypeCode
				srcAddr := ip4.SrcIP.String()
				dstAddr := ip4.DstIP.String()
				fmt.Printf("%-28s icmp  %-6d %-4d %-16s %-16s %-16s\n", ts, id, seq, typeCode.String(), srcAddr, dstAddr)
			case layers.LayerTypeTCP:
				ts := ci.Timestamp.Format(time.RFC3339Nano)
				srcAddr := ip4.SrcIP.String()
				dstAddr := ip4.DstIP.String()
				srcPort := tcp.SrcPort
				dstPort := tcp.DstPort
				fmt.Printf("%-28s tcp  %-16s %-16s %-6d %-6d\n", ts, srcAddr, dstAddr, srcPort, dstPort)
			}
		}
	}
}
