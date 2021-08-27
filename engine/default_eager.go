package engine

import (
	"context"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"time"
)

func DefaultEagerEngine(ifaceName string, filter string, ctx context.Context) {
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

	var ipCnt, ipBytes, tcpCnt, tcpBytes, udpCnt, udpBytes, icmpCnt, icmpBytes int64
	ticker := time.NewTicker(1 * time.Second)
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	ps.DecodeOptions.NoCopy = true
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
		case pkt := <-ps.Packets():
			// By default, gopacket will decode fragmented UDP packet to Segment layer.
			// To statistic fragmented UDP packet, the first IPv4 layer payload will be decoded and add to pkg layers for UDP
			ly := pkt.Layer(layers.LayerTypeIPv4)
			if ly == nil {
				continue
			}
			ipv4Layer := ly.(*layers.IPv4)
			if ipv4Layer.Flags&layers.IPv4MoreFragments == 1 && ipv4Layer.FragOffset == 0 {
				pb, ok := pkt.(gopacket.PacketBuilder)
				if !ok {
					log.Errorln("pkg is not a PacketBuilder")
				} else {
					nextDecoder := ipv4Layer.Protocol.LayerType()
					_ = nextDecoder.Decode(ipv4Layer.Payload, pb)
				}
			}

			for _, ly := range pkt.Layers() {
				switch ly.LayerType() {
				case layers.LayerTypeIPv4:
					l := ly.(*layers.IPv4)
					ipCnt++
					ipBytes += int64(l.Length)
					break
				case layers.LayerTypeTCP:
					l := ly.(*layers.TCP)
					tcpCnt++
					tcpBytes += int64(len(l.Contents) + len(l.LayerPayload()))
					break
				case layers.LayerTypeUDP:
					l := ly.(*layers.UDP)
					udpCnt++
					udpBytes += int64(l.Length)
					break
				case layers.LayerTypeICMPv4:
					l := ly.(*layers.ICMPv4)
					icmpCnt++
					icmpBytes += int64(len(l.Contents) + len(l.LayerPayload()))
					break
				}
			}
		}
	}
}
