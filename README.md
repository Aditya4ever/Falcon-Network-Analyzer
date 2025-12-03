# Falcon Network Analyzer

An enterprise-grade, automated PCAP analysis tool designed to detect complex network issues like TCP timeouts, retransmissions, and application latency.

## 🚀 Features

*   **Automated Analysis**: Detects "Dillon's Symptoms" (Low MSS + High Retransmissions + Timeouts).
*   **High Performance**: Streaming Go backend handles gigabyte-scale PCAP files.
*   **Visual Dashboard**: React-based UI for visualizing streams and issues.
*   **Privacy Focused**: Runs locally or on-premise; data stays in your control.

## 🏗️ Architecture

*   **Frontend**: React, TypeScript, Tailwind CSS, Vite
*   **Backend**: Go (Golang), Gin, gopacket
*   **Database**: PostgreSQL (Analysis Results)
*   **Cache**: Redis (Job Queue)

## 🛠️ Getting Started

### Prerequisites
*   Go 1.21+
*   Node.js 18+
*   Docker & Docker Compose

### Running Locally

1.  **Start Infrastructure** (Postgres & Redis)
    ```bash
    cd backend/deployments/docker
    docker-compose up -d
    ```

2.  **Start Backend**
    ```bash
    cd backend
    go mod tidy
    go run cmd/server/main.go
    ```

3.  **Start Frontend**
    ```bash
    cd frontend
    npm install
    npm run dev
    ```

4.  Open `http://localhost:5173` in your browser.

## 📝 License
MIT
