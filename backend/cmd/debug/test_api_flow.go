package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/debug/test_api_flow.go <path_to_pcap>")
		return
	}

	filePath := os.Args[1]
	uploadURL := "http://localhost:8080/api/upload"

	// 1. Upload File
	fmt.Println("Uploading file:", filePath)
	id, err := uploadFile(uploadURL, filePath)
	if err != nil {
		fmt.Println("Upload failed:", err)
		return
	}
	fmt.Println("Upload successful. Analysis ID:", id)

	// 2. Poll for Completion
	analysisURL := fmt.Sprintf("http://localhost:8080/api/analysis/%s", id)
	for {
		status, response, err := getAnalysis(analysisURL)
		if err != nil {
			fmt.Println("Polling failed:", err)
			return
		}

		fmt.Println("Status:", status)
		if status == "complete" {
			// Print Stream Count in Response
			streams, ok := response["streams"].([]interface{})
			if !ok {
				fmt.Println("Error: 'streams' field missing or not an array")
				// Print raw keys
				for k := range response {
					fmt.Println("Key:", k)
				}
			} else {
				fmt.Printf("API returned %d streams.\n", len(streams))
				if len(streams) > 0 {
					fmt.Println("First stream sample:", streams[0])
				}
			}
			break
		} else if status == "failed" {
			fmt.Println("Analysis failed:", response["error"])
			break
		}

		time.Sleep(1 * time.Second)
	}
}

func uploadFile(url, filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}
	io.Copy(part, file)
	writer.Close()

	req, _ := http.NewRequest("POST", url, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if id, ok := result["id"].(string); ok {
		return id, nil
	}
	return "", fmt.Errorf("no id in response")
}

func getAnalysis(url string) (string, map[string]interface{}, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, err
	}

	status, _ := result["status"].(string)
	return status, result, nil
}
