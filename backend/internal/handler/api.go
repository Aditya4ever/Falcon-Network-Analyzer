package handler

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"pcap-analyzer/internal/service/analyzer"
	"pcap-analyzer/internal/service/pcap"
	"sync"
)

// In-memory store for demo purposes (replace with Postgres later)
var (
	analysisStore = make(map[string]interface{})
	storeMutex    sync.RWMutex
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

	// Initialize state synchronously
	storeMutex.Lock()
	analysisStore[id] = gin.H{"status": "processing"}
	storeMutex.Unlock()

	// Trigger Analysis (Async in production, Sync for now)
	go func() {
		runAnalysis(id, filePath)
	}()

	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"status":  "processing",
		"message": "File uploaded successfully",
	})
}

func AnalysisResultHandler(c *gin.Context) {
	id := c.Param("id")

	storeMutex.RLock()
	result, exists := analysisStore[id]
	storeMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis not found"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func runAnalysis(id, filePath string) {
	// 1. Parse
	parser := pcap.NewStreamingParser(filePath)
	packetChan, err := parser.Parse()
	if err != nil {
		storeMutex.Lock()
		analysisStore[id] = gin.H{"status": "failed", "error": err.Error()}
		storeMutex.Unlock()
		return
	}

	// 2. Build
	builder := analyzer.NewStreamBuilder()
	for pkt := range packetChan {
		builder.ProcessPacket(pkt)
	}

	// 3. Analyze
	engine := analyzer.NewEngine()
	streams := builder.GetStreams()

	issuesCount := 0
	for _, stream := range streams {
		engine.AnalyzeStream(stream)
		if stream.Severity != "normal" {
			issuesCount++
		}
	}

	// Store result
	storeMutex.Lock()
	analysisStore[id] = gin.H{
		"status": "complete",
		"summary": gin.H{
			"total_streams": len(streams),
			"issues_found":  issuesCount,
		},
		"streams": streams,
	}
	storeMutex.Unlock()
}
