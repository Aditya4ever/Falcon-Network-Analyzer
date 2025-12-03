package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"pcap-analyzer/backend/internal/service/analyzer"
	"pcap-analyzer/backend/internal/service/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <pcap_file>")
		return
	}

	filePath := os.Args[1]

	// 1. Parse
	fmt.Println("Parsing...")
	parser := pcap.NewStreamingParser(filePath)
	packetChan, err := parser.Parse()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// 2. Build Streams
	fmt.Println("Building Streams...")
	builder := analyzer.NewStreamBuilder()
	count := 0
	for pkt := range packetChan {
		builder.ProcessPacket(pkt)
		count++
	}
	fmt.Printf("Processed %d packets.\n", count)

	// 3. Analyze
	fmt.Println("Analyzing...")
	engine := analyzer.NewEngine()
	streams := builder.GetStreams()

	start := time.Now()
	issuesFound := 0

	for _, stream := range streams {
		engine.AnalyzeStream(stream)
		if stream.Severity == "critical" || stream.Severity == "warning" {
			issuesFound++
			fmt.Printf("\n[Stream %s] %s\n", stream.ID, stream.Severity)
			fmt.Printf("  %s -> %s (%s)\n", stream.ClientIP, stream.ServerIP, stream.Protocol)
			fmt.Printf("  Stats: %d pkts, %d retrans, %d RSTs\n",
				stream.Stats.PacketCount,
				stream.Stats.RetransmissionCount,
				stream.Stats.ResetCount)
			for _, issue := range stream.Analysis {
				fmt.Printf("  - %s\n", issue)
			}
		}
	}

	fmt.Printf("\nAnalysis Complete in %v. Found %d problematic streams out of %d total.\n",
		time.Since(start), issuesFound, len(streams))
}
