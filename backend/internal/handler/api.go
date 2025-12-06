package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"pcap-analyzer/internal/db"
	"pcap-analyzer/internal/model"
	"pcap-analyzer/internal/service/analyzer"
	"pcap-analyzer/internal/service/pcap"
)

func UploadHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// Generate ID and save file
	id := uuid.New().String()
	uploadDir := "./uploads"
	os.MkdirAll(uploadDir, os.ModePerm)

	filePath := filepath.Join(uploadDir, id+".pcap")
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Initialize Analysis in DB
	analysis := model.Analysis{
		ID:        id,
		Status:    "processing",
		CreatedAt: time.Now(),
	}
	if err := db.DB.Create(&analysis).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create analysis record"})
		return
	}

	// Trigger Analysis (Async)
	go func() {
		runAnalysis(id, filePath)
	}()

	c.JSON(http.StatusOK, gin.H{
		"id":     id,
		"status": "processing",
	})
}

func AnalysisResultHandler(c *gin.Context) {
	id := c.Param("id")

	// Parse query params for filtering
	srcIP := c.Query("src_ip")
	dstIP := c.Query("dst_ip")
	protocol := c.Query("protocol")

	var analysis model.Analysis
	query := db.DB.Preload("Streams").Where("id = ?", id)

	if err := query.Preload("Streams", func(db *gorm.DB) *gorm.DB {
		filtered := db
		if srcIP != "" {
			filtered = filtered.Where("client_ip LIKE ?", "%"+srcIP+"%")
		}
		if dstIP != "" {
			filtered = filtered.Where("server_ip LIKE ?", "%"+dstIP+"%")
		}
		if protocol != "" {
			filtered = filtered.Where("protocol LIKE ?", "%"+protocol+"%")
		}
		return filtered.Order("start_time asc")
	}).First(&analysis).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found: " + err.Error()})
		return
	}

	// Parse Summary JSON for response
	var summaryMap map[string]interface{}
	if analysis.Summary != "" {
		json.Unmarshal([]byte(analysis.Summary), &summaryMap)
	}

	// Construct response to match frontend expectation
	response := gin.H{
		"status":  analysis.Status,
		"summary": summaryMap,
		"streams": analysis.Streams,
	}

	if analysis.Status == "failed" {
		response["error"] = analysis.Error
	}

	c.JSON(http.StatusOK, response)
}

func GetStreamPacketsHandler(c *gin.Context) {
	streamID := c.Param("id")
	var packets []model.Packet

	if err := db.DB.Where("stream_id = ?", streamID).Order("timestamp asc").Find(&packets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch packets"})
		return
	}

	c.JSON(http.StatusOK, packets)
}

type IngestRequest struct {
	FilePath string `json:"file_path"`
}

func DevIngestHandler(c *gin.Context) {
	var req IngestRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	id := uuid.New().String()

	// Create analysis record
	analysis := model.Analysis{
		ID:        id,
		Status:    "processing",
		CreatedAt: time.Now(),
	}
	if err := db.DB.Create(&analysis).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create record"})
		return
	}

	go runAnalysis(id, req.FilePath)

	c.JSON(http.StatusOK, gin.H{"id": id, "status": "processing"})
}

func runAnalysis(id, filePath string) {
	// 1. Parse
	db.DB.Model(&model.Analysis{}).Where("id = ?", id).Update("progress", 10)

	parser := pcap.NewStreamingParser(filePath)
	packetChan, err := parser.Parse()
	if err != nil {
		db.DB.Model(&model.Analysis{}).Where("id = ?", id).Updates(model.Analysis{
			Status: "failed",
			Error:  err.Error(),
		})
		return
	}

	// 2. Build
	db.DB.Model(&model.Analysis{}).Where("id = ?", id).Update("progress", 30)
	builder := analyzer.NewStreamBuilder()
	for pkt := range packetChan {
		builder.ProcessPacket(pkt)
	}

	// 3. Analyze
	db.DB.Model(&model.Analysis{}).Where("id = ?", id).Update("progress", 60)
	engine := analyzer.NewEngine()
	domainStreams := builder.GetStreams()

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
			StartTime:           ds.Stats.StartTime.Sub(time.Time{}).Seconds(), // Simplified timestamp
			EndTime:             ds.Stats.EndTime.Sub(time.Time{}).Seconds(),
		}

		// Convert Domain Packets to Model Packets
		for _, pkt := range ds.Packets {
			// Join flags
			flags := ""
			if len(pkt.Flags) > 0 {
				flags = pkt.Flags[0]
				for i := 1; i < len(pkt.Flags); i++ {
					flags += "," + pkt.Flags[i]
				}
			}

			mp := model.Packet{
				StreamID:   streamUUID,
				Timestamp:  pkt.Timestamp,
				SrcIP:      pkt.SrcIP,
				DstIP:      pkt.DstIP,
				Seq:        pkt.Seq,
				Ack:        pkt.Ack,
				Flags:      flags,
				PayloadLen: pkt.PayloadLen,
				WindowSize: int(pkt.Window),
				Payload:    pkt.Payload,
			}
			ms.Packets = append(ms.Packets, mp)
		}

		modelStreams = append(modelStreams, ms)
	}

	// Batch Insert Streams
	if len(modelStreams) > 0 {
		if err := db.DB.CreateInBatches(modelStreams, 100).Error; err != nil {
			// If insert fails, mark analysis as failed
			db.DB.Model(&model.Analysis{}).Where("id = ?", id).Updates(model.Analysis{
				Status: "failed",
				Error:  "Failed to save streams: " + err.Error(),
			})
			return
		}
	}

	// Update Analysis Status
	summary := gin.H{
		"total_streams": len(modelStreams),
		"issues_found":  issuesCount,
	}
	summaryJSON, _ := json.Marshal(summary)

	db.DB.Model(&model.Analysis{}).Where("id = ?", id).Updates(model.Analysis{
		Status:   "complete",
		Progress: 100,
		Summary:  string(summaryJSON),
	})
}
