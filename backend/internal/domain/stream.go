package domain

import (
	"fmt"
	"time"
)

type Severity string

const (
	SeverityNormal   Severity = "normal"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Stream represents a reconstructed TCP connection
type Stream struct {
	ID         string   `json:"id"`
	ClientIP   string   `json:"client_ip"`
	ServerIP   string   `json:"server_ip"`
	ClientPort uint16   `json:"client_port"`
	ServerPort uint16   `json:"server_port"`
	Protocol   string   `json:"protocol"`
	Severity   Severity `json:"severity"`

	ClientMSS uint16 `json:"client_mss"`
	ServerMSS uint16 `json:"server_mss"`

	Packets  []*PacketMeta `json:"packets,omitempty"`
	Stats    StreamStats   `json:"stats"`
	Analysis []string      `json:"analysis"`
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
}

type PacketMeta struct {
	Timestamp  time.Time
	SrcIP      string
	DstIP      string
	Seq        uint32
	Ack        uint32
	Flags      []string
	PayloadLen int
	Payload    []byte
	IsRetrans  bool
	Window     uint16
}

// GenerateStreamID creates a consistent ID for the 5-tuple
func GenerateStreamID(srcIP, dstIP string, srcPort, dstPort uint16) string {
	if srcIP < dstIP {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}
