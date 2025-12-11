Project: C-Shark (concise implementation summary)

This project is a simple, terminal-based packet sniffer implemented in C using libpcap. The code captures packets at the link layer and performs multi-layer decoding (Ethernet → IP → TCP/UDP/ICMP), prints human-friendly summaries, and optionally shows hex dumps of packet payloads.

Key implementation details
- Capture: Uses libpcap to open an interface (or `any`) and run a live capture loop. Ctrl+C gracefully stops the capture and returns to the interactive menu.
- Filtering: Applies user-supplied BPF filters (for example: `tcp port 80`). Note: this implementation treats HTTP by filtering on port numbers (e.g. `tcp port 80`) rather than a protocol-level `http` dissector — so you will see all traffic on that port, including TCP handshakes and ACKs, not only HTTP payload packets.
- Decoding: Layers are decoded and displayed with readable fields:
	- Layer 2: Ethernet addresses and EtherType
	- Layer 3: IPv4/IPv6 headers (addresses, TTL, flags)
	- Layer 4: TCP/UDP/ICMP headers (ports, sequence/ack, flags)
	- HTTP: Basic payload detection and simple decoding when TCP payload looks like HTTP
- Sessions & Inspection: Captured packets are stored in an in-memory session. The interactive inspector shows a session summary table and lets you examine individual packets with detailed layer-by-layer analysis and hex dumps.

Files of interest
- `src/main.c`      — program entry, argument parsing, interactive menu
- `src/capture.c`   — libpcap setup, capture loop, layer decoding callbacks
- `src/inspect.c`   — session inspection, packet summary and detailed analysis
- `src/filter.c`    — interactive/filter helpers (BPF menus)
- `src/session.c`   — stores captured packets for post-capture inspection

Usage notes
- Build with: `make` (requires libpcap development headers and root privileges for live capture)
- Run with sudo for capturing: `sudo ./cshark` or use flags like `-i <iface>` and `-f "tcp port 80"` for non-interactive capture
- Hexdump: Enable with `-x` to print packet payloads in hex

Why the port-based HTTP filtering mention matters
Using `tcp port 80` captures every packet whose TCP endpoint is port 80 — that includes the HTTP payloads but also the TCP handshake (SYN/ACK) and pure ACKs. Wireshark's `http` display filter is a higher-level check that shows only packets it recognizes as containing HTTP messages. We intentionally show the lower-level port-based view to expose the full conversation on that port (same applies to port 443 / HTTPS).
