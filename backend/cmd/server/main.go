package main

import (
	"fmt"
	"log"
	"net/http"

	"pcap-analyzer/backend/internal/handler"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "up",
			"service": "pcap-analyzer-backend",
		})
	})

	// API Routes
	r.POST("/api/upload", handler.UploadHandler)
	r.GET("/api/analysis/:id", handler.AnalysisResultHandler)

	fmt.Println("Server starting on :8080...")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
