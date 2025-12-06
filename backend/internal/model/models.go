package model

import (
	"time"
)

type Analysis struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	Status    string    `json:"status"`   // "processing", "complete", "failed"
	Progress  int       `json:"progress"` // 0-100
	CreatedAt time.Time `json:"created_at"`
	Summary   string    `json:"summary"` // JSON string of summary stats
	Error     string    `json:"error,omitempty"`
	Streams   []Stream  `gorm:"foreignKey:AnalysisID" json:"streams,omitempty"`
}

type Stream struct {
	ID                  string   `gorm:"primaryKey" json:"id"`     // UUID
	StreamHash          string   `gorm:"index" json:"stream_hash"` // 5-tuple hash
	AnalysisID          string   `gorm:"index" json:"analysis_id"`
	ClientIP            string   `json:"client_ip"`
	ServerIP            string   `json:"server_ip"`
	ServerPort          uint16   `json:"server_port"`
	Protocol            string   `json:"protocol"`
	Severity            string   `json:"severity"` // "normal", "warning", "critical"
	PacketCount         int      `json:"packet_count"`
	RetransmissionCount int      `json:"retransmission_count"`
	ResetCount          int      `json:"reset_count"`
	HasTimeout          bool     `json:"has_timeout"`
	AnalysisIssues      string   `json:"analysis_issues"` // JSON string array of issues
	StartTime           float64  `json:"start_time"`
	EndTime             float64  `json:"end_time"`
	Packets             []Packet `gorm:"foreignKey:StreamID" json:"packets,omitempty"`
}

type Packet struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	StreamID   string    `gorm:"index" json:"stream_id"`
	Timestamp  time.Time `json:"timestamp"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	Seq        uint32    `json:"seq"`
	Ack        uint32    `json:"ack"`
	Flags      string    `json:"flags"` // Comma-separated
	PayloadLen int       `json:"payload_len"`
	WindowSize int       `json:"window_size"`
	Payload    []byte    `json:"payload"` // Raw bytes
}
