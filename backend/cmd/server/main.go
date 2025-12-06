package main

import (
	"fmt"
	"log"
	"net/http"

	"pcap-analyzer/internal/db"
	"pcap-analyzer/internal/handler"
	"pcap-analyzer/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize Database
	db.InitDB()

	r := gin.Default()
	r.Use(middleware.CORSMiddleware())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "up",
			"service": "pcap-analyzer-backend",
		})
	})

	// API Routes
	api := r.Group("/api")
	{
		api.POST("/upload", handler.UploadHandler)
		api.GET("/analysis/:id", handler.AnalysisResultHandler)
		api.GET("/stream/:id/packets", handler.GetStreamPacketsHandler)
		api.POST("/dev/ingest", handler.DevIngestHandler)
	}

	fmt.Println("Server starting on :8080...")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
