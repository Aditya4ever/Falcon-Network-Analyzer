package pcap

import (
	"encoding/binary"
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
	Payload    []byte
	MSS        uint16
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
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil // Only IPv4 for now
	}
	ip, _ := ipLayer.(*layers.IPv4)

	meta := &PacketMeta{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		Length:    len(packet.Data()),
	}

	// Transport Layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	var payload []byte

	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		meta.SrcPort = uint16(tcp.SrcPort)
		meta.DstPort = uint16(tcp.DstPort)
		meta.Protocol = "TCP"
		meta.Seq = tcp.Seq
		meta.Ack = tcp.Ack
		meta.Window = tcp.Window
		meta.PayloadLen = len(tcp.Payload)
		payload = tcp.Payload

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

		// Extract MSS
		for _, opt := range tcp.Options {
			if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) == 2 {
				meta.MSS = binary.BigEndian.Uint16(opt.OptionData)
			}
		}
	} else if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		meta.SrcPort = uint16(udp.SrcPort)
		meta.DstPort = uint16(udp.DstPort)
		meta.Protocol = "UDP"
		meta.PayloadLen = len(udp.Payload)
		payload = udp.Payload
	} else {
		return nil // Skip non-TCP/UDP
	}

	// Copy Payload (Limit to 2KB)
	if len(payload) > 0 {
		limit := 2048
		if len(payload) < limit {
			limit = len(payload)
		}
		meta.Payload = make([]byte, limit)
		copy(meta.Payload, payload[:limit])
	}

	// Application Protocol Detection (DPI)
	if len(payload) > 0 {
		// HTTP Methods
		sPayload := string(payload)
		if len(sPayload) > 5 {
			prefix := sPayload[:5]
			if prefix[:3] == "GET" || prefix[:4] == "POST" || prefix[:3] == "PUT" || prefix[:4] == "HEAD" || prefix[:4] == "HTTP" {
				meta.Protocol = "HTTP"
			} else if prefix[:4] == "SSH-" {
				meta.Protocol = "SSH"
			}
		}

		// TLS (Handshake 0x16 + Version 0x03 0x01/02/03)
		if len(payload) > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
			meta.Protocol = "TLS"
		}

		// DNS (Port 53 heuristic for now)
		if meta.Protocol == "UDP" && (meta.SrcPort == 53 || meta.DstPort == 53) {
			meta.Protocol = "DNS"
		}
	}

	return meta
}
