package pcap

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketMeta contains minimal metadata for analysis
type PacketMeta struct {
	Timestamp  time.Time
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	Length     int
	Flags      []string
	Seq        uint32
	Ack        uint32
	Window     uint16
	PayloadLen int
}

// StreamingParser handles PCAP parsing
type StreamingParser struct {
	FilePath string
}

// NewStreamingParser creates a new parser
func NewStreamingParser(filePath string) *StreamingParser {
	return &StreamingParser{
		FilePath: filePath,
	}
}

// Parse streams packets to a channel
func (p *StreamingParser) Parse() (<-chan PacketMeta, error) {
	handle, err := pcap.OpenOffline(p.FilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap: %v", err)
	}

	out := make(chan PacketMeta, 1000)

	go func() {
		defer handle.Close()
		defer close(out)

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		// Optimize: Lazy decoding for speed
		packetSource.DecodeOptions = gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		}

		for packet := range packetSource.Packets() {
			meta := extractMeta(packet)
			if meta != nil {
				out <- *meta
			}
		}
	}()

	return out, nil
}

func extractMeta(packet gopacket.Packet) *PacketMeta {
	// Fast path: Only process IPv4/TCP for now
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return nil
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	meta := &PacketMeta{
		Timestamp:  packet.Metadata().Timestamp,
		SrcIP:      ip.SrcIP.String(),
		DstIP:      ip.DstIP.String(),
		SrcPort:    uint16(tcp.SrcPort),
		DstPort:    uint16(tcp.DstPort),
		Protocol:   "TCP",
		Length:     len(packet.Data()),
		Seq:        tcp.Seq,
		Ack:        tcp.Ack,
		Window:     tcp.Window,
		PayloadLen: len(tcp.Payload),
	}

	// Extract flags
	if tcp.SYN {
		meta.Flags = append(meta.Flags, "SYN")
	}
	if tcp.ACK {
		meta.Flags = append(meta.Flags, "ACK")
	}
	if tcp.FIN {
		meta.Flags = append(meta.Flags, "FIN")
	}
	if tcp.RST {
		meta.Flags = append(meta.Flags, "RST")
	}
	if tcp.PSH {
		meta.Flags = append(meta.Flags, "PSH")
	}

	return meta
}
