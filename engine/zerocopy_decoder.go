package engine

import (
	"context"
	"github.com/fs714/goiftop/engine/decoder"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"strings"
	"time"
)

func ZeroCopyDecoderEngine(ifaceName string, filter string, ctx context.Context) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("failed to OpenLive by pcap, err: %s", err.Error())
		os.Exit(0)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Errorf("failed to set BPF filter, err: %s", err.Error())
		os.Exit(0)
	}

	defer handle.Close()

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

	dec := decoder.NewLayerDecoder(DecodingLayerList...)

	firstLayer := dec.GetFirstLayerType(handle.LinkType())
	if firstLayer == gopacket.LayerTypeZero {
		log.Infoln("failed to find first decode layer type")
		os.Exit(0)
	}

	decoded := make([]gopacket.LayerType, 0, 4)
	var ipCnt, ipBytes, tcpCnt, tcpBytes, udpCnt, udpBytes, icmpCnt, icmpBytes int64
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ipPps := ipCnt
			ipRate := float64(ipBytes*8/1000) / 1000
			tcpPps := tcpCnt
			tcpRate := float64(tcpBytes*8/1000) / 1000
			udpPps := udpCnt
			udpRate := float64(udpBytes*8/1000) / 1000
			icmpPps := icmpCnt
			icmpRate := float64(icmpBytes*8/1000) / 1000

			log.Infof("IpPPS: %d, IpRate: %.2f, TcpPPS: %d, TcpRate: %.2f, UdpPPS: %d, UdpRate: %.2f, IcmpPPS: %d, IcmpRate: %.2f",
				ipPps, ipRate, tcpPps, tcpRate, udpPps, udpRate, icmpPps, icmpRate)

			ipCnt = 0
			ipBytes = 0
			tcpCnt = 0
			tcpBytes = 0
			udpCnt = 0
			udpBytes = 0
			icmpCnt = 0
			icmpBytes = 0
		default:
			data, _, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				log.Infof("error getting packet: %s", err.Error())
				continue
			}

			err = dec.DecodeLayers(data, firstLayer, &decoded)
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

			for _, ly := range decoded {
				switch ly {
				case layers.LayerTypeIPv4:
					ipCnt++
					ipBytes += int64(ipv4.Length)
					break
				case layers.LayerTypeTCP:
					tcpCnt++
					tcpBytes += int64(len(tcp.Contents) + len(tcp.LayerPayload()))
					break
				case layers.LayerTypeUDP:
					udpCnt++
					udpBytes += int64(udp.Length)
					break
				case layers.LayerTypeICMPv4:
					icmpCnt++
					icmpBytes += int64(len(icmpv4.Contents) + len(icmpv4.LayerPayload()))
					break
				}
			}
		}
	}
}
