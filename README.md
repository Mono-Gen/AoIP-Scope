# AoIP-Scope: Professional Audio over IP Network Analyzer

A high-precision command-line analysis and live capture tool for AoIP (AES67, Dante, ST 2110-30/31) network audio streams.

![AoIP-Scope Interactive CLI Demo](./assets/aoip_scope.gif)

---

## Features
- **Deep Packet Analysis**: Offline analysis of PCAP/PCAPNG capture files, checking PTP Grandmaster stability, packet loss, duplicate packets, and inter-arrival jitter.
- **High-Fidelity Audio Decoding**: Decodes 24-bit (L24) and 16-bit (L16) raw PCM streams, performs automated micro-anomaly scans (clipping, silence drop), and exports bit-perfect audio as WAV files.
- **Live Packet Capture**: Memory-safe streaming capture supporting both passive monitoring (Mirror mode) and active multicast subscription (IGMPv2 Join/Leave).
- **Diagnostics Reporting**: Automatic discovery of Dante & network devices via mDNS, SAP/SDP stream discovery, and customizable JSON report export.
- **Sleek CLI Interface**: Beautiful console formatting, table views, and real-time progress indicators powered by `rich`.

---

## Prerequisites & Requirements

For offline PCAP/PCAPNG file analysis (`analyze` subcommand), no special capture drivers are required. However, for live capturing:
1. **Npcap**: Installation of **Npcap** (with WinPcap API compatibility) is mandatory on Windows for live capturing (`record`) and listing interfaces (`ifaces`).
2. **Administrator Rights**: Launching terminal (Command Prompt / PowerShell) with "Run as Administrator" is required to capture live raw network packets.

---

## Getting Started

### 1. Installation
Clone the repository and install the dependencies listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 2. Offline PCAP Analysis (Primary Feature)
Analyze a PCAP/PCAPNG file to scan streams, inspect PTP Grandmaster status, and check stream health:
```bash
python aoip_scope.py analyze path/to/capture.pcapng
```
*(Note: Subcommand `analyze` can be omitted, as `python aoip_scope.py path/to/capture.pcapng` also triggers the analysis for backward compatibility).*

To export a specific stream (SSRC) as a WAV audio file:
```bash
python aoip_scope.py analyze path/to/capture.pcapng --ssrc 0x4B3D2A1C --out output.wav
```

To extract channel 1 only from a multi-channel stream as a single mono WAV:
```bash
python aoip_scope.py analyze path/to/capture.pcapng --ssrc 0x4B3D2A1C --mono 1 --out ch1_output.wav
```

To generate a detailed JSON diagnostic report:
```bash
python aoip_scope.py analyze path/to/capture.pcapng --report
```

### 3. Live Packet Capture
Capture live AoIP multicast streams into a PCAPNG file (Requires Administrator privileges & Npcap):
```bash
# Passive mirroring from NIC index 1 for 10 seconds:
python aoip_scope.py record -i 1 -o capture.pcapng -m mirror -t 10

# Active capture subscribing to a specific multicast IP via IGMP Join:
python aoip_scope.py record -i 1 -o capture.pcapng -m join --ip 239.69.100.1 -t 10
```

### 4. Listing Available Network Interfaces
Find the correct NIC index (1-based number) or description for your hardware:
```bash
python aoip_scope.py ifaces
```

---

## Detailed Manuals

For in-depth explanations, advanced arguments, and troubleshooting, please refer to our localized manuals:
- **Japanese User Manual**: [manual_JA.md](./docs/manual_JA.md)
- **English User Manual**: [manual_EN.md](./docs/manual_EN.md)

---

## License
MIT
