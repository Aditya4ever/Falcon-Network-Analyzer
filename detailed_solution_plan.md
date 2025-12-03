# Expertise Network Trace Analysis Solution Plan

## Executive Summary
This plan outlines the development of a specialized, browser-based PCAP analysis tool designed to automatically detect and visualize specific network anomalies, particularly those identified in "Expertise Network Trace Analysis" scenarios (e.g., "Dillon's" symptoms: low MSS, high retransmissions, timeouts leading to RSTs). The tool will move beyond simple packet listing to provide actionable "Expertise" insights.

## I. Core Architecture & Technology Stack

### Frontend Framework
*   **React**: For a dynamic, responsive Single Page Application (SPA).
*   **Tailwind CSS**: For rapid, professional, and custom styling.
*   **Vite**: For fast build tooling and local development.

### Data Processing (The "Engine")
*   **Primary Parser**: `pcap-ng-parser` (or similar WASM/JS library) for initial rapid prototyping.
*   **Alternative/Robust Parser**: **Kaitai Struct**. If the primary parser fails on complex files, we will switch to Kaitai Struct, which offers a declarative and highly robust way to parse binary formats (see `research_notes.md`).
*   **Custom Analysis Logic**: A dedicated JavaScript/TypeScript module to iterate over parsed packets and reconstruct TCP streams.

### Persistence & State
*   **Firebase Firestore**: To store *analysis results* (not necessarily the raw PCAP, to save bandwidth) and shareable reports.
*   **Firebase Auth**: For user identity and secure access to reports.

## II. Detailed Implementation Phases

### Phase 1: Foundation & In-Browser Parsing
**Goal**: A working React app that can ingest a PCAP file and output raw packet data in memory.

1.  **Project Initialization**:
    *   Setup Vite + React + TypeScript.
    *   Configure Tailwind CSS.
    *   Initialize Firebase (Auth & Firestore).
2.  **File Ingestion**:
    *   Create a Drag-and-Drop zone for `.pcap` and `.pcapng` files.
    *   Implement `FileReader` to read files as `ArrayBuffer`.
3.  **Parsing Logic**:
    *   Integrate `pcap-ng-parser`.
    *   **Milestone**: Successfully log an array of packet objects (Timestamp, Src IP, Dst IP, Protocol, Length, Payload) to the console.

### Phase 2: The "Expertise" Analysis Engine
**Goal**: Transform raw packets into "Conversations" and detect specific anomalies.

1.  **Stream Reconstruction**:
    *   Group packets by 5-tuple: `(SrcIP, DstIP, SrcPort, DstPort, Protocol)`.
    *   Handle TCP state tracking (SYN, SYN-ACK, ESTABLISHED, FIN/RST).
2.  **Symptom Detection Algorithms**:
    *   **MSS Analysis**: Check SYN packets for Maximum Segment Size options. Flag if MSS < 1300 (indicates potential fragmentation/MTU issues, e.g., "Dillon's low MSS").
    *   **Retransmission Detection**: Identify duplicate Sequence Numbers with the same payload length. Calculate % retransmission per stream.
    *   **Timeout/RST Analysis**: Detect long gaps (Delta > 1s, 3s, etc.) followed immediately by an RST flag. This is the signature "Application Timeout" pattern.
    *   **Zero Window**: Detect Window Size = 0 events.

### Phase 3: Visualization & UI
**Goal**: Present the data not as a list of 10,000 packets, but as a list of "Issues".

1.  **Dashboard View**:
    *   **Summary Cards**: "Total Streams", "High Severity Issues", "Avg MSS".
    *   **Issues List**: A prioritized list of detected problems (e.g., "Stream #4: High Retransmission (15%)", "Stream #9: Application Timeout after 45s").
2.  **Stream Detail View**:
    *   **Ladder Diagram (Sequence Diagram)**: A visual representation of the packet flow for a *single* selected stream.
    *   **Highlighting**: Color-code packets involved in retransmissions (Red) or timeouts (Yellow gaps).
    *   **Metadata Panel**: Show negotiated MSS, Window Scaling, and Timestamps.

### Phase 4: Reporting & Sharing
**Goal**: Allow the user to save and share their findings.

1.  **Report Generation**:
    *   Generate a JSON summary of the analysis.
    *   Save to Firestore.
2.  **Shareable Links**:
    *   Create a unique URL (e.g., `/report/:reportId`) that loads the analysis from Firestore.

## III. Data Structure Design

```typescript
interface Packet {
  id: number;
  timestamp: number;
  src: string;
  dst: string;
  protocol: string;
  flags: string[]; // ['SYN', 'ACK']
  seq: number;
  ack: number;
  window: number;
  mss?: number; // Parsed from options
  length: number;
}

interface Stream {
  id: string; // "192.168.1.5:54321-10.0.0.1:443"
  packets: Packet[];
  stats: {
    startTime: number;
    endTime: number;
    retransmissions: number;
    minMSS: number;
    maxMSS: number;
    hasRST: boolean;
    hasTimeout: boolean;
  };
  analysis: string[]; // ["Low MSS Detected (1260)", "Connection Reset after 30s idle"]
}
```

## IV. Next Steps
1.  Initialize the repository.
2.  Install dependencies (`pcap-ng-parser`, `firebase`, `react-router-dom`).
3.  Begin Phase 1: File Upload & Basic Parsing.
