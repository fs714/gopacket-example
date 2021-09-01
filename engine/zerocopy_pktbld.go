package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/fs714/goiftop/utils/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"os"
	"runtime/debug"
	"time"
)

// LayerDump outputs a very verbose string representation of a layer.  Its
// output is a concatenation of LayerString(l) and hex.Dump(l.LayerContents()).
// It contains newlines and ends with a newline.
func LayerDump(l gopacket.Layer) string {
	var b bytes.Buffer
	b.WriteString(gopacket.LayerString(l))
	b.WriteByte('\n')
	if d, ok := l.(gopacket.Dumper); ok {
		dump := d.Dump()
		if dump != "" {
			b.WriteString(dump)
			if dump[len(dump)-1] != '\n' {
				b.WriteByte('\n')
			}
		}
	}
	b.WriteString(hex.Dump(l.LayerContents()))
	return b.String()
}

// DecodeFailure is a packet layer created if decoding of the packet data failed
// for some reason.  It implements ErrorLayer.  LayerContents will be the entire
// set of bytes that failed to parse, and Error will return the reason parsing
// failed.
type DecodeFailure struct {
	data  []byte
	err   error
	stack []byte
}

// Error returns the error encountered during decoding.
func (d *DecodeFailure) Error() error { return d.err }

// LayerContents implements Layer.
func (d *DecodeFailure) LayerContents() []byte { return d.data }

// LayerPayload implements Layer.
func (d *DecodeFailure) LayerPayload() []byte { return nil }

// String implements fmt.Stringer.
func (d *DecodeFailure) String() string {
	return "Packet decoding error: " + d.Error().Error()
}

// Dump implements Dumper.
func (d *DecodeFailure) Dump() (s string) {
	if d.stack != nil {
		s = string(d.stack)
	}
	return
}

// LayerType returns LayerTypeDecodeFailure
func (d *DecodeFailure) LayerType() gopacket.LayerType { return gopacket.LayerTypeDecodeFailure }

var errNilDecoder = errors.New("NextDecoder passed nil decoder, probably an unsupported decode type")

// MyPacketBuilder is a PacketBuilder implementation that does eager decoding. Upon
// initial construction, it decodes all the layers it can from packet data.
type MyPacketBuilder struct {
	// data contains the entire packet data for a packet
	data []byte
	// layers contains each layer we've already decoded
	layers []gopacket.Layer
	// last is the last layer added to the packet
	last gopacket.Layer
	// metadata is the PacketMetadata for this packet
	metadata gopacket.PacketMetadata

	decodeOptions gopacket.DecodeOptions

	// Pointers to the various important layers
	link        gopacket.LinkLayer
	network     gopacket.NetworkLayer
	transport   gopacket.TransportLayer
	application gopacket.ApplicationLayer
	failure     gopacket.ErrorLayer
}

func (p *MyPacketBuilder) SetTruncated() {
	p.metadata.Truncated = true
}

func (p *MyPacketBuilder) AddLayer(l gopacket.Layer) {
	p.layers = append(p.layers, l)
	p.last = l
}

func (p *MyPacketBuilder) SetLinkLayer(l gopacket.LinkLayer) {
	if p.link == nil {
		p.link = l
	}
}

func (p *MyPacketBuilder) SetNetworkLayer(l gopacket.NetworkLayer) {
	if p.network == nil {
		p.network = l
	}
}

func (p *MyPacketBuilder) SetTransportLayer(l gopacket.TransportLayer) {
	if p.transport == nil {
		p.transport = l
	}
}

func (p *MyPacketBuilder) SetApplicationLayer(l gopacket.ApplicationLayer) {
	if p.application == nil {
		p.application = l
	}
}

func (p *MyPacketBuilder) SetErrorLayer(l gopacket.ErrorLayer) {
	if p.failure == nil {
		p.failure = l
	}
}

func (p *MyPacketBuilder) NextDecoder(next gopacket.Decoder) error {
	if next == nil {
		return errNilDecoder
	}
	if p.last == nil {
		return errors.New("NextDecoder called, but no layers added yet")
	}

	d := p.last.LayerPayload()
	if len(d) == 0 {
		return nil
	}

	// By default, IPv4 layer will decode fragmented packet to Segment layer.
	// To statistic fragmented packet, the first IPv4 layer payload will be decoded
	if p.last.LayerType() == layers.LayerTypeIPv4 {
		ipv4Layer := p.last.(*layers.IPv4)
		if ipv4Layer.Flags&layers.IPv4MoreFragments == 1 && ipv4Layer.FragOffset == 0 {
			next = ipv4Layer.Protocol.LayerType()
		}
	}

	// Since we're eager, immediately call the next decoder.
	return next.Decode(d, p)
}

func (p *MyPacketBuilder) DumpPacketData() {
	_, _ = fmt.Fprint(os.Stderr, p.packetDump())
	_ = os.Stderr.Sync()
}

func (p *MyPacketBuilder) DecodeOptions() *gopacket.DecodeOptions {
	return &p.decodeOptions
}

func (p *MyPacketBuilder) Metadata() *gopacket.PacketMetadata {
	return &p.metadata
}

func (p *MyPacketBuilder) Data() []byte {
	return p.data
}

func (p *MyPacketBuilder) packetString() string {
	var b bytes.Buffer
	_, _ = fmt.Fprintf(&b, "PACKET: %d bytes", len(p.Data()))
	if p.metadata.Truncated {
		b.WriteString(", truncated")
	}
	if p.metadata.Length > 0 {
		_, _ = fmt.Fprintf(&b, ", wire length %d cap length %d", p.metadata.Length, p.metadata.CaptureLength)
	}
	if !p.metadata.Timestamp.IsZero() {
		_, _ = fmt.Fprintf(&b, " @ %v", p.metadata.Timestamp)
	}
	b.WriteByte('\n')
	for i, l := range p.layers {
		_, _ = fmt.Fprintf(&b, "- Layer %d (%02d bytes) = %s\n", i+1, len(l.LayerContents()), gopacket.LayerString(l))
	}
	return b.String()
}

func (p *MyPacketBuilder) packetDump() string {
	var b bytes.Buffer
	_, _ = fmt.Fprintf(&b, "-- FULL PACKET DATA (%d bytes) ------------------------------------\n%s", len(p.data), hex.Dump(p.data))
	for i, l := range p.layers {
		_, _ = fmt.Fprintf(&b, "--- Layer %d ---\n%s", i+1, LayerDump(l))
	}
	return b.String()
}

func (p *MyPacketBuilder) addFinalDecodeError(err error, stack []byte) {
	fail := &DecodeFailure{err: err, stack: stack}
	if p.last == nil {
		fail.data = p.data
	} else {
		fail.data = p.last.LayerPayload()
	}
	p.AddLayer(fail)
	p.SetErrorLayer(fail)
}

func (p *MyPacketBuilder) recoverDecodeError() {
	if !p.decodeOptions.SkipDecodeRecovery {
		if r := recover(); r != nil {
			p.addFinalDecodeError(fmt.Errorf("%v", r), debug.Stack())
		}
	}
}

func (p *MyPacketBuilder) LinkLayer() gopacket.LinkLayer {
	return p.link
}

func (p *MyPacketBuilder) NetworkLayer() gopacket.NetworkLayer {
	return p.network
}

func (p *MyPacketBuilder) TransportLayer() gopacket.TransportLayer {
	return p.transport
}

func (p *MyPacketBuilder) ApplicationLayer() gopacket.ApplicationLayer {
	return p.application
}

func (p *MyPacketBuilder) ErrorLayer() gopacket.ErrorLayer {
	return p.failure
}

func (p *MyPacketBuilder) Layers() []gopacket.Layer {
	return p.layers
}

func (p *MyPacketBuilder) Layer(t gopacket.LayerType) gopacket.Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}

func (p *MyPacketBuilder) initialDecode(dec gopacket.Decoder) {
	defer p.recoverDecodeError()
	err := dec.Decode(p.data, p)
	if err != nil {
		p.addFinalDecodeError(err, nil)
	}
}

func ZeroCopyPacketBuilderEngine(ifaceName string, filter string, ctx context.Context) {
	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
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
			data, ci, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				log.Errorf("error getting packet: %v", err)
				continue
			}

			options := gopacket.DecodeOptions{
				Lazy:                     false,
				NoCopy:                   true,
				SkipDecodeRecovery:       false,
				DecodeStreamsAsDatagrams: false,
			}
			pkt := &MyPacketBuilder{
				data:          data,
				decodeOptions: options,
			}
			pkt.initialDecode(handle.LinkType())

			m := pkt.Metadata()
			m.CaptureInfo = ci
			m.Truncated = m.Truncated || ci.CaptureLength < ci.Length

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
