package main

import (
	"fmt"
	"pcap-analyzer/internal/db"
	"pcap-analyzer/internal/model"
)

func main() {
	db.InitDB()

	var analysis model.Analysis
	// Get the latest analysis
	if err := db.DB.Order("created_at desc").Preload("Streams").First(&analysis).Error; err != nil {
		fmt.Println("Error fetching analysis:", err)
		return
	}

	fmt.Printf("Analysis ID: %s\n", analysis.ID)
	fmt.Printf("Status: %s\n", analysis.Status)
	fmt.Printf("Summary: %s\n", analysis.Summary)
	fmt.Printf("Stream Count (in DB relation): %d\n", len(analysis.Streams))

	// Check Packets
	var packets []model.Packet
	if err := db.DB.Limit(5).Find(&packets).Error; err != nil {
		fmt.Println("Error fetching packets:", err)
	} else {
		fmt.Println("--- Dumping first 5 packets in DB ---")
		for _, p := range packets {
			fmt.Printf("ID: %d, StreamID: %s, Seq: %d, Win: %d, Len: %d\n", p.ID, p.StreamID, p.Seq, p.WindowSize, p.PayloadLen)
		}
	}
}
