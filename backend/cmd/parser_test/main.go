package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"pcap-analyzer/backend/internal/service/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <pcap_file>")
		return
	}

	filePath := os.Args[1]
	fmt.Printf("Analyzing %s...\n", filePath)

	parser := pcap.NewStreamingParser(filePath)
	packetChan, err := parser.Parse()
	if err != nil {
		log.Fatalf("Failed to start parser: %v", err)
	}

	count := 0
	start := time.Now()

	for pkt := range packetChan {
		count++
		if count%1000 == 0 {
			fmt.Printf("\rProcessed %d packets...", count)
		}
		// Simple debug output for first 5 packets
		if count <= 5 {
			fmt.Printf("[%s] %s:%d -> %s:%d [%v] Seq=%d\n",
				pkt.Timestamp.Format(time.StampMilli),
				pkt.SrcIP, pkt.SrcPort,
				pkt.DstIP, pkt.DstPort,
				pkt.Flags, pkt.Seq)
		}
	}

	duration := time.Since(start)
	fmt.Printf("\nDone! Processed %d packets in %v (%.2f packets/sec)\n",
		count, duration, float64(count)/duration.Seconds())
}
