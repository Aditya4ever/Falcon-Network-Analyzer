# Project Progress Tracker

## Phase 1: The "Engine" (Backend Foundation)
- [x] **Init**: Setup Go module.
- [x] **Parser**: Implement `gopacket` streaming reader.
- [x] **Stream Reassembly**: Build the 5-tuple hash map to track TCP states.
- [x] **Analyzer Modules**:
    - [x] *Retransmission Detector*: Track duplicate sequence numbers.
    - [x] *Timing Analyzer*: Calculate deltas (SYN->SYN-ACK, Request->Response).
    - [x] *Pattern Matcher*: Implement "Dillon's Symptoms" logic (Low MSS + High Retrans + Timeout).
    - [x] *Protocol Detection*: Basic HTTP and TLS detection.
    - [x] *MSS Extraction*: Extract MSS from TCP Options.

## Phase 2: The API & Storage
- [x] **API**: Create `POST /upload` (streaming upload) and `GET /analysis/:id`.
- [x] **Persistence**: Design schema for `Analyses`, `Streams`.
    - *Note*: Implemented using **SQLite** and **GORM** for robust local persistence without Docker dependency.
- [ ] **Job Queue**: Use Redis to track "Processing", "Completed", "Failed" states.
    - *Current*: Using Go goroutines (async) with synchronous state initialization.

## Phase 3: The Frontend Dashboard
- [x] **Upload UI**: Drag-and-drop zone with progress bar.
- [x] **Dashboard**: Summary cards (Total Streams, Issues Found).
- [x] **Stream List**: Virtualized list/Table to handle streams.
    - *Note*: Implemented with **Pagination** (Top 50) and **Filtering** (Source, Dest, Protocol) for performance.
- [ ] **Detail View**: The "Ladder Diagram" (Sequence Diagram).

## Phase 4: Advanced Visuals & Polish
- [x] **Network Topology**: Use **React Flow** to visualize connections between IPs.
- [x] **Packet Drill-down**: Use **react-hex-editor** (or custom) to display raw packet payloads.
- [x] **Timeline View**: Implement a "Ladder Diagram" using **Recharts**.
- [ ] **Advanced Protocol Detection**: Integrate **go-dpi** for deep packet inspection.
- [ ] **Reporting**: Export to PDF/JSON.

## Infrastructure & DevOps
- [x] **Docker Setup**: Dockerfiles and Compose created (but currently using local dev due to environment issues).
- [x] **Local Dev**: Configured **Vite Proxy** to bypass CORS issues seamlessly.
- [x] **Git**: Repository initialized and code pushed to GitHub.
