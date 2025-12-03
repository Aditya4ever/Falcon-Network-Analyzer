# Research Notes: PCAP Parsing & Analysis Tools

## 1. PCAP File Analysis
**Status**: No `.pcap`, `.pcapng`, or `.cap` files were found in the current workspace (`c:\Users\arc4e\source\AG\PCAP`).
**Action**: Analysis of specific trace files is pending user upload or provision of files.

## 2. JavaScript PCAP Parsing Libraries
Research into the current state of JavaScript/WASM PCAP parsing (as of late 2024) reveals the following:

### A. Kaitai Struct (Recommended for Robustness)
*   **Description**: A declarative binary format parsing language. You define the file structure in `.ksy` (YAML) and it compiles to a JavaScript runtime parser.
*   **Pros**:
    *   **Extremely Robust**: Handles edge cases and complex binary structures better than ad-hoc parsers.
    *   **Maintainable**: The logic is in the spec, not the code.
    *   **Pure JS**: No native bindings required.
*   **Cons**: Steeper learning curve (requires compiling `.ksy` files).

### B. pcap-ng-parser
*   **Description**: A specialized parser for the newer `.pcapng` format.
*   **Pros**: Easier to drop in for simple PCAPNG files.
*   **Cons**: Limited protocol support (often just Ethernet/IPv4/TCP) and may not handle older `.pcap` files or complex pcapng blocks well.

### C. node_pcap / @audc/pcap
*   **Description**: Bindings to the native `libpcap` C library.
*   **Pros**: Fast, standard.
*   **Cons**: **Not suitable for browser environments** (requires Node.js backend).

## 3. Web-Based Network Analysis Tools (Inspiration)
*   **ntopng**: A gold standard for web-based traffic analysis. Key features to emulate:
    *   Flow-based visualization (Sankey diagrams).
    *   "Top Talkers" charts.
*   **Sniffnet**: A Rust-based tool with a very modern, clean UI. Good inspiration for the "Dashboard" aesthetic.
*   **Wireshark (WASM ports)**: There are experimental ports of Wireshark to WASM (e.g., `sharkd`), but they are often too heavy for a lightweight web tool.

## 4. Recommendation for "Expertise" Solution
For the **Expertise Network Trace Analysis** solution, we should:
1.  **Start with `pcap-ng-parser`** (or a similar lightweight JS parser) for Phase 1 to get immediate results.
2.  **Evaluate Kaitai Struct** if we encounter parsing errors or need to support a wider range of PCAP variants.
3.  **Focus on "Flow" Logic**: The core value is not just parsing packets, but reconstructing the *TCP State Machine* in JavaScript to detect the specific "Expertise" symptoms (MSS, Retransmissions, Timeouts).
