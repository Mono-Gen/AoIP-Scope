# AoIP-Scope User Manual (English Version)

AoIP-Scope is a professional Command-Line Interface (CLI) diagnostic tool designed to capture live Audio over IP (AoIP) multicast streams (such as AES67 and ST 2110-30/31) on network interfaces, and perform in-depth analysis of PTP synchronization stability, packet loss, and jitter.

---

## 1. Environment & Prerequisites

To ensure the correct operation of this tool, the following environment is required:

- **Supported OS**: Windows 10 / 11 (64-bit)
- **Capture Driver**: **Npcap** (or WinPcap) installation is mandatory.
  - *Note*: If Npcap is not installed, network interface retrieval (`ifaces`) and live packet capturing (`record`) will not function.
  - Please download and install Npcap from the official website beforehand.
- **Execution Rights**: Capturing network packets in real-time (`record`) requires **Administrator rights**. Please launch your Command Prompt or PowerShell with "Run as Administrator".
  - *Note*: Administrator rights and Npcap are NOT required if you are only performing offline PCAP file analysis (`analyze`).

---

## 2. Installation

1. Extract the provided ZIP file (`AoIP-Scope_v0.9.0.zip`) into any desired directory.
2. The executable file `aoip_scope.exe` in the extracted folder is the standalone application.

---

## 3. Basic Usage & Subcommands

AoIP-Scope provides three primary subcommands:

1. **`analyze`**: Reads a PCAP/PCAPNG file, performs stream inventory/health diagnostics, analyzes PTP synchronization, and extracts decoded audio.
2. **`record`**: Captures live AoIP packets on a network interface and saves them as a PCAPNG file.
3. **`ifaces`**: Lists all available network interfaces.

---

### 3.1 `analyze` Subcommand
Performs in-depth diagnostics on the captured PCAP/PCAPNG file. Offline analysis and audio decoding do not require Npcap installation or Administrator privileges.
*Note: For backwards compatibility, the `analyze` subcommand name itself can be omitted, and the tool will automatically default to analysis if a file path is provided.*

**Key Arguments:**
- `pcap` : File path to the PCAP/PCAPNG file to be analyzed.
- `--list` : Lists discovered streams and network devices and exits immediately without detailed packet analysis or decoding.
- `--ssrc` : The target stream's SSRC in hexadecimal (e.g., `0x12345678`) for audio extraction and payload analysis.
- `--out` : Output WAV filename for the extracted audio.
- `--mono` : The 1-based channel number to extract as a single mono WAV file from a multi-channel stream.
- `--report` : Generates a detailed JSON diagnostic report.

**Example (Perform full stream analysis and summary display):**
```powershell
.\aoip_scope.exe analyze ./raw_capture.pcapng
```

**Example (Quick list of streams only):**
```powershell
.\aoip_scope.exe analyze ./raw_capture.pcapng --list
```

**Example (Extract audio from a specific SSRC and save to a WAV file):**
```powershell
.\aoip_scope.exe analyze ./raw_capture.pcapng --ssrc 0x4B3D2A1C --out ./extracted_audio.wav
```

**Example (Extract channel 1 only as a mono WAV):**
```powershell
.\aoip_scope.exe analyze ./raw_capture.pcapng --ssrc 0x4B3D2A1C --mono 1 --out ./extracted_ch1.wav
```

**Example (Generate a detailed JSON diagnostic report):**
```powershell
.\aoip_scope.exe analyze ./raw_capture.pcapng --report
```
*The diagnostic report will be saved automatically in the current directory as `report_YYYYMMDD_HHMMSS.json`.*

---

### 3.2 `record` Subcommand
Captures packets from a specified network interface in real-time and writes them to a file.
*Note: Running this subcommand requires Npcap installation and Administrator rights.*

**Key Arguments:**
- `-i`, `--interface` : The index (1-based number) or the name of the target NIC.
- `-o`, `--out` : Output filename (default: `capture.pcapng`).
- `-m`, `--mode` : Capture mode. Choose either `mirror` (passive SPAN port monitoring) or `join` (active IGMP multicast membership request) (default: `mirror`).
- `--ip` : The multicast IP address to join in `join` mode (e.g., `239.69.100.1`).
- `-t`, `--duration` : Capture duration in seconds. If omitted, the tool continues capturing until manually stopped with `Ctrl+C`.

**Example (Passive capture from a mirror port for 10 seconds):**
```powershell
.\aoip_scope.exe record -i 1 -o ./raw_capture.pcapng -m mirror -t 10
```

**Example (Active capture by sending an IGMP Join request to a multicast group for 5 seconds):**
```powershell
.\aoip_scope.exe record -i 1 -o ./stream_capture.pcapng -m join --ip 239.69.100.1 -t 5
```

---

### 3.3 `ifaces` Subcommand
Displays the list of available Network Interface Cards (NICs), including their IP addresses and MAC addresses. Use this subcommand to identify the "index" or "name" of the target NIC for the `record` command.
*Note: Running this subcommand requires Npcap installation.*

**Example:**
```powershell
.\aoip_scope.exe ifaces
```

---

## 4. Troubleshooting

### 4.1 Capture fails to start, or the network interface list is empty
- **Cause 1**: `Npcap` is not installed.
  - *Solution*: Install Npcap. It is recommended to check "Support raw 802.11 traffic (and monitor mode) for wireless adapters" or ensure WinPcap API compatibility is enabled during installation.
- **Cause 2**: The command line was not launched with Administrator privileges.
  - *Solution*: Re-launch your Command Prompt or PowerShell with "Run as Administrator".

### 4.2 Analysis results show "No active RTP streams found"
- **Cause 1**: There is no actual AoIP audio traffic flowing on the captured network interface.
  - *Solution*: Verify that the correct NIC index was specified via `ifaces`. Also, ensure that Port Mirroring (SPAN) is configured correctly on the network switch.
- **Cause 2**: The network environment requires active multicast stream request.
  - *Solution*: Run the `record` command using `-m join` mode and specify the exact multicast IP address (`--ip`) of the audio stream you want to receive.

### 4.3 Audio extraction fails or outputs "SKIP: Not a raw PCM stream"
- **Cause**: The stream's audio format is not L24 or L16 PCM, or it does not use a valid dynamic RTP payload type (96–127).
  - *Solution*: Check the "Format" column in the analysis summary to confirm that the stream is an AES67 / Dante compliant 24-bit PCM (L24) or 16-bit PCM (L16) stream.

---

## 5. WAV File Size Calculations and Examples (Advanced Reference)

The size of the WAV audio files extracted by this tool is mathematically bound to AoIP-specific protocol parameters (packet transmission interval: `ptime`) and the capture duration (total packet count).

The WAV file size (in bytes) is uniquely determined by the following formula:

$$\text{File Size} = (\text{Total Frames} \times \text{Channels} \times \text{Bytes per Sample}) + 44 \text{ Bytes (WAV Header)}$$
* *Note: `Bytes per Sample` is 3 bytes for 24-bit PCM (L24) and 2 bytes for 16-bit PCM (L16).*
* *Note: `Total Frames` is calculated as $\text{Packet Count} \times \text{Samples per Packet}$.*

Below are real-world examples and breakdowns of two streams extracted from the exact same PCAPNG file.

### Example 1: Dante Multicast (AES67) Stream
* **Filename**: `extract_02CCFD32.wav`
* **Stream Parameters**: 2ch Stereo / L24 (24-bit PCM) / 48000 Hz
* **Transmission Interval (ptime)**: **1.0 ms** (**48 samples** per packet)
* **Total Captured Packets**: 40,137 packets
* **Total Frames Calculation**:
  $$40,137\text{ packets} \times 48\text{ samples} = 1,926,576\text{ frames}$$
* **Duration (seconds)**:
  $$1,926,576 \div 48,000\text{Hz} = \mathbf{40.137\text{ seconds}}$$
* **WAV File Size Calculation**:
  $$1,926,576 \times 2\text{ch} \times 3\text{bytes} + 44\text{bytes} = \mathbf{11,559,500\text{ bytes}}$$

### Example 2: Dante Unicast Stream
* **Filename**: `extract_DA434761.wav`
* **Stream Parameters**: 2ch Stereo / L24 (24-bit PCM) / 48000 Hz
* **Transmission Interval (ptime)**: **0.333 ms** (**16 samples** per packet)
* **Total Captured Packets**: 111,945 packets
* **Total Frames Calculation**:
  $$111,945\text{ packets} \times 16\text{ samples} = 1,791,120\text{ frames}$$
* **Duration (seconds)**:
  $$1,791,120 \div 48,000\text{Hz} = \mathbf{37.315\text{ seconds}}$$
* **WAV File Size Calculation**:
  $$1,791,120 \times 2\text{ch} \times 3\text{bytes} + 44\text{bytes} = \mathbf{10,746,764\text{ bytes}}$$

### Takeaways & Key Concepts
1. **Influence of Packet Transmission Interval (ptime)**:
   A Dante Unicast flow (0.333ms) transmits packets approximately 3 times more frequently than a multicast flow (1.0ms). While the packet count is drastically higher, the payload size (samples per packet) is exactly one-third.
2. **Difference in Captured Duration**:
   Due to slight capture start/stop timing offsets, the unicast flow recorded duration (37.315s) is about 2.8 seconds shorter than the multicast flow (40.137s). This duration offset translates directly to a difference of roughly 812 KB in file size.

Because AoIP-Scope performs bit-perfect data reconstruction directly from network raw payloads, the file sizes precisely reflect the underlying protocol characteristics and capture time windows.

