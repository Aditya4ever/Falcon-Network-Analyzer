package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"pcap-analyzer/internal/db"
	"pcap-analyzer/internal/model"
	"pcap-analyzer/internal/service/analyzer"
	"pcap-analyzer/internal/service/pcap"

	"github.com/google/uuid"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/debug/ingest_file.go <path_to_pcap>")
		return
	}

	filePath := os.Args[1]
	fmt.Println("Ingesting file:", filePath)

	db.InitDB()

	// Create Analysis Record
	id := uuid.New().String()
	analysis := model.Analysis{
		ID:        id,
		Status:    "processing",
		CreatedAt: time.Now(),
	}
	if err := db.DB.Create(&analysis).Error; err != nil {
		fmt.Println("Failed to create analysis:", err)
		return
	}
	fmt.Println("Created Analysis ID:", id)

	// 1. Parse
	parser := pcap.NewStreamingParser(filePath)
	packetChan, err := parser.Parse()
	if err != nil {
		fmt.Println("Parser Error:", err)
		return
	}

	// 2. Build
	builder := analyzer.NewStreamBuilder()
	packetCount := 0
	for pkt := range packetChan {
		builder.ProcessPacket(pkt)
		packetCount++
	}
	fmt.Println("Parsed Packets:", packetCount)

	// 3. Analyze
	engine := analyzer.NewEngine()
	domainStreams := builder.GetStreams()
	fmt.Println("Built Streams:", len(domainStreams))

	var modelStreams []model.Stream
	issuesCount := 0

	for _, ds := range domainStreams {
		engine.AnalyzeStream(ds)
		if ds.Severity != "normal" {
			issuesCount++
		}

		// Convert Domain Stream to Model Stream
		issuesJSON, _ := json.Marshal(ds.Analysis)
		streamUUID := uuid.New().String()

		ms := model.Stream{
			ID:                  streamUUID,
			StreamHash:          ds.ID,
			AnalysisID:          id,
			ClientIP:            ds.ClientIP,
			ServerIP:            ds.ServerIP,
			ServerPort:          ds.ServerPort,
			Protocol:            ds.Protocol,
			Severity:            string(ds.Severity),
			PacketCount:         ds.Stats.PacketCount,
			RetransmissionCount: ds.Stats.RetransmissionCount,
			ResetCount:          ds.Stats.ResetCount,
			HasTimeout:          ds.Stats.HasTimeout,
			AnalysisIssues:      string(issuesJSON),
			StartTime:           ds.Stats.StartTime.Sub(time.Time{}).Seconds(),
			EndTime:             ds.Stats.EndTime.Sub(time.Time{}).Seconds(),
		}
		modelStreams = append(modelStreams, ms)
	}

	// Batch Insert Streams
	if len(modelStreams) > 0 {
		fmt.Println("Inserting", len(modelStreams), "streams into DB...")
		if err := db.DB.CreateInBatches(modelStreams, 100).Error; err != nil {
			fmt.Println("DB Insert Error:", err)
		} else {
			fmt.Println("Successfully inserted streams.")
		}
	}

	// Update Analysis Status
	summary := map[string]interface{}{
		"total_streams": len(modelStreams),
		"issues_found":  issuesCount,
	}
	summaryJSON, _ := json.Marshal(summary)

	db.DB.Model(&model.Analysis{}).Where("id = ?", id).Updates(model.Analysis{
		Status:  "complete",
		Summary: string(summaryJSON),
	})

	fmt.Println("Analysis Complete.")
}
