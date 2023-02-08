package main

import (
	"context"
	"flag"
	"strings"
	"sync"
	"time"

	"github.com/fs714/gopacket-example/nflog/lib/ncw"
	"github.com/fs714/gopacket-example/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var group int

func init() {
	flag.IntVar(&group, "g", 0, "nflog group id")
	flag.Parse()
}

func main() {
	// # iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100
	// # iptables -t raw -A PREROUTING -i eth1 -j NFLOG --nflog-group 2 --nflog-range 64 --nflog-threshold 10
	// # iptables -t mangle -A POSTROUTING -o eth1 -j NFLOG --nflog-group 5 --nflog-range 64 --nflog-threshold 10

	var eth layers.Ethernet
	var linuxSll layers.LinuxSLL
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var dns layers.DNS
	var icmpv4 layers.ICMPv4
	var gre layers.GRE
	var llc layers.LLC
	var arp layers.ARP
	var payload gopacket.Payload

	DecodingLayerList := []gopacket.DecodingLayer{
		&eth,
		&linuxSll,
		&dot1q,
		&ipv4,
		&tcp,
		&udp,
		&dns,
		&icmpv4,
		&gre,
		&llc,
		&arp,
		&payload,
	}

	dec := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, DecodingLayerList...)
	decoded := make([]gopacket.LayerType, 0, 4)
	var ipCnt, ipBytes, tcpCnt, tcpBytes, udpCnt, udpBytes, icmpCnt, icmpBytes int64
	var mu sync.RWMutex

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fn := func(data []byte) int {
		err := dec.DecodeLayers(data, &decoded)
		if err != nil {
			ignoreErr := false
			for _, s := range []string{"TLS", "STP", "Fragment"} {
				if strings.Contains(err.Error(), s) {
					ignoreErr = true
				}
			}
			if !ignoreErr {
				log.Errorf("error decoding packet: %s", err.Error())
			}
		}

		mu.Lock()
		for _, ly := range decoded {
			switch ly {
			case layers.LayerTypeIPv4:
				ipCnt++
				ipBytes += int64(ipv4.Length)
			case layers.LayerTypeTCP:
				tcpCnt++
				tcpBytes += int64(len(tcp.Contents) + len(tcp.LayerPayload()))
			case layers.LayerTypeUDP:
				udpCnt++
				udpBytes += int64(udp.Length)
			case layers.LayerTypeICMPv4:
				icmpCnt++
				icmpBytes += int64(len(icmpv4.Contents) + len(icmpv4.LayerPayload()))
			}
		}

		//log.Infof("ipCnt: %d, ipBytes: %d, tcpCnt: %d, tcpBytes: %d, udpCnt: %d, udpBytes: %d, icmpCnt: %d, icmpBytes: %d",
		//	ipCnt, ipBytes, tcpCnt, tcpBytes, udpCnt, udpBytes, icmpCnt, icmpBytes)
		mu.Unlock()

		return 0
	}

	nflog := ncw.NewNfLog(group, fn)
	defer nflog.Close()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mu.RLock()
			ipPps := ipCnt
			ipRate := float64(ipBytes*8/1000) / 1000
			tcpPps := tcpCnt
			tcpRate := float64(tcpBytes*8/1000) / 1000
			udpPps := udpCnt
			udpRate := float64(udpBytes*8/1000) / 1000
			icmpPps := icmpCnt
			icmpRate := float64(icmpBytes*8/1000) / 1000
			mu.RUnlock()

			log.Infof("IpPPS: %d, IpRate: %.2f, TcpPPS: %d, TcpRate: %.2f, UdpPPS: %d, UdpRate: %.2f, IcmpPPS: %d, IcmpRate: %.2f",
				ipPps, ipRate, tcpPps, tcpRate, udpPps, udpRate, icmpPps, icmpRate)

			mu.Lock()
			ipCnt = 0
			ipBytes = 0
			tcpCnt = 0
			tcpBytes = 0
			udpCnt = 0
			udpBytes = 0
			icmpCnt = 0
			icmpBytes = 0
			mu.Unlock()
		}
	}
}
