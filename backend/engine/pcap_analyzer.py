import dpkt
import socket
import struct
import os
from typing import Dict, List, Tuple
try:
    from backend.models.stream import AudioStream, StreamMetadata, PacketInfo
    from .sdp_parser import SdpParser
    from .ptp_analyzer import PTPAnalyzer
    from .mdns_parser import MDNSParser
    from .heuristic_analyzer import HeuristicAnalyzer
    from .igmp_analyzer import IGMPAnalyzer
    from .payload_analyzer import PayloadAnalyzer
except ImportError:
    from models.stream import AudioStream, StreamMetadata, PacketInfo
    from engine.sdp_parser import SdpParser
    from engine.ptp_analyzer import PTPAnalyzer
    from engine.mdns_parser import MDNSParser
    from engine.heuristic_analyzer import HeuristicAnalyzer
    from engine.igmp_analyzer import IGMPAnalyzer
    from engine.payload_analyzer import PayloadAnalyzer

class PcapAnalyzer:
    def __init__(self, pcap_path: str, progress_cb=None):
        self.pcap_path = pcap_path
        self.progress_cb = progress_cb
        self.streams: Dict[int, AudioStream] = {}
        self.sap_configs: Dict[str, StreamMetadata] = {}
        self.ptp = PTPAnalyzer()
        self.mdns = MDNSParser()
        self.igmp = IGMPAnalyzer()
        self.total_size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0

    def run(self):
        """Automatically identify and analyze PCAP or PCAPNG"""
        if not os.path.exists(self.pcap_path): return
        
        try:
            with open(self.pcap_path, 'rb') as f:
                header = f.read(24)
                if len(header) < 24: return
                magic = struct.unpack("<I", header[:4])[0]
                
                # PCAPNG check
                if magic == 0x0A0D0D0A:
                    self._run_pcapng(f)
                else:
                    self._run_pcap_manual(f, magic)
                    
            self._post_process()
        except Exception as e:
            # Only print critical errors
            print(f"Critical error reading PCAP: {e}")

    def _post_process(self):
        """Post-analysis: mDNS verification and heuristic analysis"""
        for ssrc, stream in self.streams.items():
            meta = stream.metadata
            if meta.src_ip in self.mdns.dante_devices:
                meta.protocol = "Dante"
                if not meta.session_name:
                    meta.session_name = self.mdns.dante_devices[meta.src_ip]["name"]
            
            # If detailed format info via SDP is available in SAP (even if it arrived later)
            if meta.dst_ip in self.sap_configs:
                s = self.sap_configs[meta.dst_ip]
                meta.session_name, meta.channels, meta.sample_rate = s.session_name, s.channels, s.sample_rate
                meta.encoding, meta.ptime, meta.payload_type = s.encoding, s.ptime, s.payload_type
                meta.clock_domain, meta.ts_refclk, meta.mediaclk = s.clock_domain, s.ts_refclk, s.mediaclk
            else:
                HeuristicAnalyzer.analyze(stream)
            
            # Payload health analysis
            PayloadAnalyzer.analyze(stream, self)

    def _run_pcapng(self, f):
        f.seek(0)
        pcap = dpkt.pcapng.Reader(f)
        for ts, buf in pcap:
            self._process_packet(ts, buf, 0)
            if self.progress_cb: self.progress_cb(f.tell(), self.total_size)

    def _run_pcap_manual(self, f, magic):
        endian = '<' if magic in (0xA1B2C3D4, 0xA1B23C4D, 0xD4C3B2A1, 0x4D3CB2A1) else '>'
        nano_ts = magic in (0xA1B23C4D, 0x4D3CB2A1)  # nanosecond精度PCAP
        f.seek(24) # Skip PCAP global header
        while True:
            pkt_hdr_start = f.tell()
            pkt_header = f.read(16)
            if len(pkt_header) < 16: break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(f"{endian}IIII", pkt_header)
            ts = ts_sec + (ts_usec / 1e9 if nano_ts else ts_usec / 1e6)
            buf = f.read(incl_len)
            if len(buf) < incl_len: break
            self._process_packet(ts, buf, pkt_hdr_start + 16)
            if self.progress_cb: self.progress_cb(f.tell(), self.total_size)

    def _process_packet(self, ts: float, buf: bytes, offset: int):
        try:
            if len(buf) < 14: return
            eth = dpkt.ethernet.Ethernet(buf)
            
            vlan_id = None
            ip_data = None

            # Layer 2: Ethernet / VLAN
            if eth.type == dpkt.ethernet.ETH_TYPE_8021Q:
                # [Dst(6)] [Src(6)] [0x8100(2)] [TCI(2)] [Type(2)]
                tci = struct.unpack('>H', buf[14:16])[0]
                vlan_id = tci & 0x0FFF
                next_type = struct.unpack('>H', buf[16:18])[0]
                if next_type == dpkt.ethernet.ETH_TYPE_IP:
                    ip_data = dpkt.ip.IP(buf[18:])
            elif eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip_data = eth.data
            else:
                # Raw IP packet (e.g. from some tunnels)
                if (buf[0] >> 4) == 4:
                    ip_data = dpkt.ip.IP(buf)

            if not isinstance(ip_data, dpkt.ip.IP): return
            
            # Layer 3: IP / IGMP
            if ip_data.p == dpkt.ip.IP_PROTO_IGMP:
                self.igmp.process_packet(ts, ip_data.src, bytes(ip_data.data))
                return

            # Layer 3: IP / UDP
            if ip_data.p != dpkt.ip.IP_PROTO_UDP: return
            
            udp = None
            if isinstance(ip_data.data, dpkt.udp.UDP):
                udp = ip_data.data
            else:
                try: udp = dpkt.udp.UDP(ip_data.data)
                except: return # Malformed UDP

            src_mac = eth.src.hex(':')
            dst_mac = eth.dst.hex(':')
            dscp = ip_data.tos >> 2
            ttl = ip_data.ttl

            # SAP/SDP (Port 9875)
            if udp.dport == 9875:
                self._handle_sap(udp.data)

            # PTP (Port 319, 320)
            elif udp.dport in (319, 320):
                self.ptp.process_packet(ts, udp.data)

            # mDNS (Port 5353)
            elif udp.dport == 5353:
                self.mdns.process_packet(ip_data.src, udp.data)            # Dante Unicast Audio (Port in 14336-15359, starts with 02 00)
            elif (14336 <= udp.dport <= 15359 and len(udp.data) >= 10 and 
                  udp.data[:2] == b'\x02\x00'):
                rtp_packet_rel_offset = len(buf) - len(udp.data)
                self._handle_dante_unicast(ts, udp.data, socket.inet_ntoa(ip_data.src), 
                                           socket.inet_ntoa(ip_data.dst), udp.dport, 
                                           offset + rtp_packet_rel_offset, src_mac, dst_mac, dscp, ttl, vlan_id)

            # RTP (Guess by header, exclude Dante Control and standard protocols)
            elif (len(udp.data) >= 12 and (udp.data[0] & 0xC0) == 0x80 and
                  udp.dport not in {319, 320, 5353, 5355, 137, 138, 53, 9875, 1900} and
                  udp.sport not in {319, 320, 5353, 5355, 137, 138, 53, 9875, 1900} and
                  not (8700 <= udp.sport <= 8800) and not (8700 <= udp.dport <= 8800)):
                
                # Check for valid dynamic Payload Type (96-127) for AES67/Dante
                pt = udp.data[1] & 0x7F
                if not (96 <= pt <= 127): return
                rtp_packet_rel_offset = len(buf) - len(udp.data)
                self._handle_rtp(ts, udp.data, socket.inet_ntoa(ip_data.src), 
                                socket.inet_ntoa(ip_data.dst), udp.dport, 
                                offset + rtp_packet_rel_offset, src_mac, dst_mac, dscp, ttl, vlan_id)
        except Exception:
            pass # Ignore individual packet errors and continue

    def _handle_sap(self, data):
        sdp_idx = data.find(b"v=0")
        if sdp_idx != -1:
            try:
                sdp_text = data[sdp_idx:].decode('utf-8', errors='ignore')
                meta = SdpParser.parse(sdp_text)
                self.sap_configs[meta.dst_ip] = meta
            except Exception: pass

    def _handle_rtp(self, ts, rtp_buf, src_ip, dst_ip, dport, rtp_offset, src_mac, dst_mac, dscp, ttl, vlan_id):
        try:
            rtp = dpkt.rtp.RTP(rtp_buf)
            ssrc = rtp.ssrc
            if ssrc not in self.streams:
                meta = StreamMetadata(
                    ssrc=ssrc, src_ip=src_ip, dst_ip=dst_ip, dst_port=dport,
                    src_mac=src_mac, dst_mac=dst_mac, protocol="AES67",
                    dscp=dscp, ttl=ttl, vlan_id=vlan_id
                )
                if dst_ip in self.sap_configs:
                    s = self.sap_configs[dst_ip]
                    meta.session_name, meta.channels, meta.sample_rate = s.session_name, s.channels, s.sample_rate
                    meta.encoding, meta.ptime, meta.payload_type = s.encoding, s.ptime, s.payload_type
                    meta.clock_domain, meta.ts_refclk, meta.mediaclk = s.clock_domain, s.ts_refclk, s.mediaclk
                self.streams[ssrc] = AudioStream(metadata=meta)
            
            stream = self.streams[ssrc]
            self._analyze_packet_timing(stream, rtp, ts, rtp_offset, ttl)
        except Exception:
            pass

    def _handle_dante_unicast(self, ts, udp_buf, src_ip, dst_ip, dport, udp_offset, src_mac, dst_mac, dscp, ttl, vlan_id):
        try:
            if len(udp_buf) < 10: return
            
            flow_id = struct.unpack('>H', udp_buf[2:4])[0]
            val_bytes = udp_buf[4:9]
            val = int.from_bytes(val_bytes, byteorder='big')
            
            # Sequence number: derived from 5-byte sample-accurate timestamp
            # Dante low-latency flow typically packages 16 samples per packet
            seq = (val // 16) & 0xFFFF
            rtp_ts = val & 0xFFFFFFFF
            
            # Generate a pseudo-SSRC that is uniquely mapped to the unicast flow
            import hashlib
            key_str = f"{dst_ip}:{dport}"
            h = hashlib.md5(key_str.encode()).digest()
            pseudo_ssrc = 0xDA000000 | (struct.unpack('>I', h[:4])[0] & 0x00FFFFFF)
            
            if pseudo_ssrc not in self.streams:
                # Deduce channel count dynamically (standard Dante is L24, 16 samples/packet)
                payload_len = len(udp_buf) - 9
                channels = max(1, payload_len // 3 // 16)
                
                meta = StreamMetadata(
                    ssrc=pseudo_ssrc, src_ip=src_ip, dst_ip=dst_ip, dst_port=dport,
                    src_mac=src_mac, dst_mac=dst_mac, protocol="Dante (Unicast)",
                    session_name=f"Dante Unicast Flow {flow_id}",
                    encoding="L24", sample_rate=48000, channels=channels, ptime=0.333,
                    dscp=dscp, ttl=ttl, vlan_id=vlan_id
                )
                self.streams[pseudo_ssrc] = AudioStream(metadata=meta)
                
            stream = self.streams[pseudo_ssrc]
            
            # Mock RTP class for timing analysis compatibility
            class MockRTP:
                def __init__(self, seq, ts, data):
                    self.seq = seq
                    self.ts = ts
                    self.data = data
                def __len__(self):
                    return len(self.data) + 9
                    
            mock_rtp = MockRTP(seq, rtp_ts, udp_buf[9:])
            self._analyze_packet_timing(stream, mock_rtp, ts, udp_offset, ttl)
        except Exception:
            pass

    def _analyze_packet_timing(self, stream, rtp, ts, rtp_offset, ttl):
        # Discard duplicate packets (e.g. from VLAN mirroring), ignore if same sequence
        if stream.packets and stream.packets[-1].seq == rtp.seq:
            return

        arrival_diff = 0.0
        jitter = 0.0
        if stream.packets:
            last = stream.packets[-1]
            arrival_diff = ts - last.pcap_ts
            sr = stream.metadata.sample_rate if stream.metadata.sample_rate else 48000
            expected_diff = (rtp.ts - last.rtp_ts) / sr
            d = abs(arrival_diff - expected_diff)
            jitter = last.jitter + (d - last.jitter) / 16.0
        
        # Sequence analysis
        if stream.packets:
            last_seq = stream.packets[-1].seq
            diff = (rtp.seq - last_seq) & 0xFFFF
            if 1 < diff < 3000:
                stream.error_log.append({
                    "ts": ts, "type": "LOSS", "seq_missing": (last_seq + 1) & 0xFFFF, 
                    "count": diff - 1, "index": len(stream.packets)
                })

        header_len = len(rtp) - len(rtp.data)
        pkt_info = PacketInfo(
            seq=rtp.seq, rtp_ts=rtp.ts, pcap_ts=ts, 
            payload_offset=rtp_offset + header_len,
            payload_len=len(rtp.data),
            jitter=jitter, arrival_diff=arrival_diff
        )
        stream.packets.append(pkt_info)
        stream.stats["max_jitter"] = max(stream.stats["max_jitter"], jitter)
        stream.stats["min_ttl"] = min(stream.stats["min_ttl"], ttl)
        stream.stats["max_ttl"] = max(stream.stats["max_ttl"], ttl)

    def load_payloads(self, ssrc: int) -> List[Tuple[int, bytes]]:
        """For WAV export (batch load)"""
        if ssrc not in self.streams: return []
        res = []
        try:
            with open(self.pcap_path, 'rb') as f:
                for p in self.streams[ssrc].packets:
                    f.seek(p.payload_offset)
                    res.append((p.seq, f.read(p.payload_len)))
        except: pass
        return res

    def iter_payloads(self, ssrc: int):
        """Generator for analysis (memory-safe streaming load)"""
        if ssrc not in self.streams: return
        try:
            with open(self.pcap_path, 'rb') as f:
                for p in self.streams[ssrc].packets:
                    f.seek(p.payload_offset)
                    yield p.seq, p.pcap_ts, f.read(p.payload_len)
        except: pass
