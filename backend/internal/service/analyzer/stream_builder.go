package analyzer

import (
	"sync"

	"pcap-analyzer/backend/internal/domain"
	"pcap-analyzer/backend/internal/service/pcap"
)

// StreamBuilder handles the reconstruction of streams from packets
type StreamBuilder struct {
	streams map[string]*domain.Stream
	mu      sync.RWMutex
}

func NewStreamBuilder() *StreamBuilder {
	return &StreamBuilder{
		streams: make(map[string]*domain.Stream),
	}
}

// ProcessPacket adds a packet to the appropriate stream
func (sb *StreamBuilder) ProcessPacket(pkt pcap.PacketMeta) {
	streamID := domain.GenerateStreamID(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream, exists := sb.streams[streamID]
	if !exists {
		stream = &domain.Stream{
			ID:         streamID,
			ClientIP:   pkt.SrcIP,
			ServerIP:   pkt.DstIP,
			ClientPort: pkt.SrcPort,
			ServerPort: pkt.DstPort,
			Protocol:   pkt.Protocol,
			Stats: domain.StreamStats{
				StartTime: pkt.Timestamp,
				MinMSS:    9999, // Init high
			},
			Severity: "normal",
		}
		sb.streams[streamID] = stream
	}

	// Update Stats
	stream.Stats.PacketCount++
	stream.Stats.EndTime = pkt.Timestamp
	stream.Stats.Duration = stream.Stats.EndTime.Sub(stream.Stats.StartTime)

	// Convert pcap.PacketMeta to domain.PacketMeta (lighter weight)
	dPkt := &domain.PacketMeta{
		Timestamp:  pkt.Timestamp,
		Seq:        pkt.Seq,
		Ack:        pkt.Ack,
		Flags:      pkt.Flags,
		PayloadLen: pkt.PayloadLen,
	}
	stream.Packets = append(stream.Packets, dPkt)
}

// GetStreams returns all built streams
func (sb *StreamBuilder) GetStreams() []*domain.Stream {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	result := make([]*domain.Stream, 0, len(sb.streams))
	for _, s := range sb.streams {
		result = append(result, s)
	}
	return result
}
