package analyzer

import (
	"fmt"
	"time"

	"pcap-analyzer/internal/domain"
)

// Engine runs the analysis algorithms on streams
type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

// AnalyzeStream runs all detection logic on a single stream
func (e *Engine) AnalyzeStream(stream *domain.Stream) {
	e.detectRetransmissions(stream)
	e.detectResetsAndTimouts(stream)
	e.detectDillonsSymptoms(stream)
}

func (e *Engine) detectRetransmissions(stream *domain.Stream) {
	seqMap := make(map[uint32]int)
	retransCount := 0

	for _, pkt := range stream.Packets {
		// Only track packets with payload
		if pkt.PayloadLen > 0 {
			seqMap[pkt.Seq]++
			if seqMap[pkt.Seq] > 1 {
				retransCount++
				pkt.IsRetrans = true
			}
		}
	}

	stream.Stats.RetransmissionCount = retransCount
	if retransCount > 0 {
		rate := float64(retransCount) / float64(stream.Stats.PacketCount) * 100
		if rate > 5.0 {
			stream.Analysis = append(stream.Analysis, fmt.Sprintf("High Retransmission Rate: %.2f%%", rate))
			stream.Severity = "warning"
		}
	}
}

func (e *Engine) detectResetsAndTimouts(stream *domain.Stream) {
	var lastPktTime time.Time
	rstCount := 0
	hasTimeout := false

	for i, pkt := range stream.Packets {
		// Check for RST
		for _, flag := range pkt.Flags {
			if flag == "RST" {
				rstCount++
				// Check gap before RST
				if i > 0 {
					gap := pkt.Timestamp.Sub(lastPktTime)
					// 9.6s is the magic number from the requirements
					if gap > 9*time.Second && gap < 11*time.Second {
						stream.Analysis = append(stream.Analysis, fmt.Sprintf("Timeout Pattern: RST after %.2fs gap", gap.Seconds()))
						hasTimeout = true
						stream.Severity = "critical"
					}
				}
			}
		}
		lastPktTime = pkt.Timestamp
	}

	stream.Stats.ResetCount = rstCount
	stream.Stats.HasTimeout = hasTimeout
}

func (e *Engine) detectDillonsSymptoms(stream *domain.Stream) {
	// "Dillon's Symptoms": Low MSS + High Retrans + Timeout
	// Note: MSS is not yet extracted in parser, assuming we add it later.
	// For now, check Retrans + Timeout

	if stream.Stats.RetransmissionCount > 10 && stream.Stats.HasTimeout {
		stream.Analysis = append(stream.Analysis, "MATCH: Dillon's Symptoms (High Retrans + Timeout)")
		stream.Severity = "critical"
	}
}
