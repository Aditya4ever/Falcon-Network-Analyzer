package domain

import (
	"fmt"
	"time"
)

// Stream represents a reconstructed TCP connection
type Stream struct {
	ID         string `json:"id"`
	ClientIP   string `json:"client_ip"`
	ServerIP   string `json:"server_ip"`
	ClientPort uint16 `json:"client_port"`
	ServerPort uint16 `json:"server_port"`
	Protocol   string `json:"protocol"`

	Packets  []*PacketMeta `json:"packets,omitempty"` // Pointer to avoid copying
	Stats    StreamStats   `json:"stats"`
	Analysis []string      `json:"analysis"`
	Severity string        `json:"severity"` // "critical", "warning", "info"
}

// StreamStats holds aggregate metrics
type StreamStats struct {
	StartTime           time.Time     `json:"start_time"`
	EndTime             time.Time     `json:"end_time"`
	Duration            time.Duration `json:"duration"`
	PacketCount         int           `json:"packet_count"`
	RetransmissionCount int           `json:"retransmission_count"`
	ResetCount          int           `json:"reset_count"`
	HasTimeout          bool          `json:"has_timeout"`
	MinMSS              int           `json:"min_mss"`
}

// PacketMeta (redefined here to avoid circular imports if needed,
// or we can move the one from pcap package here. For now, let's assume
// we import it or define a shared one. I'll define a clean one for domain usage)
type PacketMeta struct {
	Timestamp  time.Time
	Seq        uint32
	Ack        uint32
	Flags      []string
	PayloadLen int
	IsRetrans  bool
}

// GenerateStreamID creates a consistent ID for the 5-tuple
// Sorts IP/Port pairs to ensure A->B and B->A map to same stream
func GenerateStreamID(srcIP, dstIP string, srcPort, dstPort uint16) string {
	if srcIP < dstIP {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}
