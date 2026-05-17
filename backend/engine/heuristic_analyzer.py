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
            
        # 2. Infer encoding and number of channels
        # Test both L24 (3 bytes/sample) and L16 (2 bytes/sample) and pick
        # whichever gives a result closest to a whole number of channels.
        payload_len = packets[0].payload_len

        channels = 2  # default
        encoding = "L24"

        if samples_per_packet > 0:
            calc_l24 = payload_len / (samples_per_packet * 3)
            calc_l16 = payload_len / (samples_per_packet * 2)

            # Fractional deviation from nearest integer (lower = better fit)
            err_l24 = abs(calc_l24 - round(calc_l24))
            err_l16 = abs(calc_l16 - round(calc_l16))

            if err_l16 < err_l24 and 0 < calc_l16 < 128:
                # L16 fits more cleanly
                encoding = "L16"
                channels = max(1, round(calc_l16))
            elif 0 < calc_l24 < 128:
                encoding = "L24"
                channels = max(1, round(calc_l24))
        
        # Apply inferred results
        stream.metadata.sample_rate = estimated_sr
        stream.metadata.channels = channels
        stream.metadata.encoding = encoding
        stream.metadata.ptime = (samples_per_packet / estimated_sr) * 1000
        stream.metadata.is_heuristic = True
