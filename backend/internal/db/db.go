package db

import (
	"log"
	"pcap-analyzer/internal/model"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	var err error
	// Use a local file 'pcap.db' for persistence
	DB, err = gorm.Open(sqlite.Open("pcap.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto Migrate the schema
	err = DB.AutoMigrate(&model.Analysis{}, &model.Stream{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database initialized and migrated successfully.")
}
