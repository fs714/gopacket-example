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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for {
		select {
		case packet := <-packets:
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("not a tcp packet")
				continue
			}

			ip4 := packet.NetworkLayer().(*layers.IPv4)
			tcp := packet.TransportLayer().(*layers.TCP)
			ts := packet.Metadata().Timestamp.Format(time.RFC3339Nano)
			srcAddr := ip4.SrcIP.String()
			dstAddr := ip4.DstIP.String()
			srcPort := tcp.SrcPort
			dstPort := tcp.DstPort
			fmt.Printf("%-28s tcp  %-16s %-16s %-6d %-6d\n", ts, srcAddr, dstAddr, srcPort, dstPort)
		}
	}
}
