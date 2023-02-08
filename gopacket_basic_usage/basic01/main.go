package main

import (
	"flag"
	"fmt"
	"log"
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
		panic(err)
	}
	if err := handle.SetBPFFilter(""); err != nil {
		panic(err)
	}

	for {
		data, ci, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			fmt.Printf("error getting packet: %s\n", err.Error())
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			log.Println("not a tcp packet")
			continue
		}

		ip4 := packet.NetworkLayer().(*layers.IPv4)
		tcp := packet.TransportLayer().(*layers.TCP)
		ts := ci.Timestamp.Format(time.RFC3339Nano)
		srcAddr := ip4.SrcIP.String()
		dstAddr := ip4.DstIP.String()
		srcPort := tcp.SrcPort
		dstPort := tcp.DstPort
		fmt.Printf("%-28s tcp  %-16s %-16s %-6d %-6d\n", ts, srcAddr, dstAddr, srcPort, dstPort)
	}
}
