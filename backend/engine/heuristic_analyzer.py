from typing import List
try:
    from backend.models.stream import StreamMetadata, PacketInfo, AudioStream
except ImportError:
    from models.stream import StreamMetadata, PacketInfo, AudioStream

class HeuristicAnalyzer:
    @staticmethod
    def analyze(stream: AudioStream):
        """
        Infer sample rate and channels from RTP packet behavior
        """
        if len(stream.packets) < 2:
            return

        packets = stream.packets
        
        # 1. Infer sample rate
        # Use the first and last packets (or packets with some interval) to find a stable packet interval.
        # Calculate using the overall difference to reduce the impact of packet loss, etc.
        first_pkt = packets[0]
        last_pkt = packets[-1]
        
        # Consider timestamp looping, but take simple difference assuming the PCAP is short
        ts_diff = (last_pkt.rtp_ts - first_pkt.rtp_ts) & 0xFFFFFFFF
        time_diff = last_pkt.pcap_ts - first_pkt.pcap_ts
        
        estimated_sr = 48000
        if time_diff > 0:
            raw_sr = ts_diff / time_diff
            # Round to the nearest standard rate (44100, 48000, 96000)
            if 43000 < raw_sr < 45000:
                estimated_sr = 44100
            elif 47000 < raw_sr < 49000:
                estimated_sr = 48000
            elif 95000 < raw_sr < 97000:
                estimated_sr = 96000
            else:
                # Default
                estimated_sr = 48000
        
        # 2. Infer number of channels
        # Inference assuming L24 (24-bit = 3 bytes/sample) is standard for Dante/AES67
        payload_len = packets[0].payload_len
        # RTP Timestamp increment (samples per packet)
        # Search for packets with contiguous sequence numbers
        samples_per_packet = 48  # Default (1ms @ 48kHz)
        for i in range(1, min(10, len(packets))):
            if (packets[i].seq - packets[i-1].seq) & 0xFFFF == 1:
                samples_per_packet = (packets[i].rtp_ts - packets[i-1].rtp_ts) & 0xFFFFFFFF
                break
                
        if samples_per_packet == 0:
            samples_per_packet = estimated_sr // 1000 # Assume 1ms
            
        bytes_per_sample_per_ch = 3 # L24
        
        # channels = payload_len / (samples_per_packet * 3)
        channels = 2 # default
        if samples_per_packet > 0:
            calc_ch = payload_len / (samples_per_packet * bytes_per_sample_per_ch)
            if 0 < calc_ch < 128:
                channels = max(1, round(calc_ch))
        
        # Apply inferred results
        stream.metadata.sample_rate = estimated_sr
        stream.metadata.channels = channels
        stream.metadata.encoding = "L24"
        stream.metadata.ptime = (samples_per_packet / estimated_sr) * 1000
        stream.metadata.is_heuristic = True
