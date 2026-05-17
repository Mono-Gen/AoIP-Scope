import numpy as np
from datetime import datetime
try:
    from backend.models.stream import AudioStream
    from backend.engine.audio_engine import AudioEngine
except ImportError:
    from models.stream import AudioStream
    from engine.audio_engine import AudioEngine

class PayloadAnalyzer:
    @staticmethod
    def analyze(stream: AudioStream, pcap_analyzer):
        """
        Fast scan payload (L24/L16) health (clipping and silence drops) using Numpy.
        Processes in chunk units using a generator to save memory.
        """
        meta = stream.metadata
        if meta.encoding not in ("L24", "L16"):
            stream.stats["payload_health"] = {"status": "SKIP", "msg": "Not a raw PCM stream"}
            return

        sr = meta.sample_rate if meta.sample_rate else 48000
        ch = meta.channels if meta.channels else 2
        
        # Continuous silence threshold (e.g., 10ms = 480 samples at 48kHz)
        silence_threshold_samples = int(sr * 0.01) * ch 
        
        # Clipping threshold
        max_val = 8388607 if meta.encoding == "L24" else 32767
        min_val = -8388608 if meta.encoding == "L24" else -32768

        clip_events = []
        silence_events = []
        
        current_silence_samples = 0
        total_samples_processed = 0
        first_pcap_ts = None
        
        for seq, pcap_ts, payload_bytes in pcap_analyzer.iter_payloads(meta.ssrc):
            if first_pcap_ts is None:
                first_pcap_ts = pcap_ts
                
            samples = AudioEngine.decode_rtp(payload_bytes, ch, meta.encoding)
            if samples.size == 0:
                continue
                
            # Flatten array for faster contiguous scanning
            flat_samples = samples.flatten()
            chunk_size = len(flat_samples)
            
            # 1. Clipping detection (Vectorized)
            clips = np.where((flat_samples >= max_val) | (flat_samples <= min_val))[0]
            if len(clips) > 0:
                # Record relative time of the first clip found in the chunk
                first_clip_idx = clips[0]
                absolute_sample_idx = total_samples_processed + first_clip_idx
                relative_sec = (absolute_sample_idx // ch) / sr
                
                # Record only one representative event to prevent flooding within the same chunk
                if len(clip_events) < 50: # Limit log size
                    clip_events.append({
                        "rel_sec": relative_sec,
                        "pcap_ts": pcap_ts, # Approximate absolute time
                        "abs_time": datetime.fromtimestamp(pcap_ts).isoformat(),
                        "count": len(clips)
                    })

            # 2. Silence detection (Vectorized)
            zeros = (flat_samples == 0)
            if np.all(zeros):
                current_silence_samples += chunk_size
            else:
                if current_silence_samples > 0:
                    # Strict calculations when zeroes span across chunk boundaries are complex,
                    # so we simply check if all-zero chunks exceed the threshold.
                    if current_silence_samples >= silence_threshold_samples:
                        start_silence_idx = total_samples_processed - current_silence_samples
                        rel_sec = (start_silence_idx // ch) / sr
                        if len(silence_events) < 50:
                            silence_events.append({
                                "rel_sec": rel_sec,
                                "pcap_ts": pcap_ts, 
                                "abs_time": datetime.fromtimestamp(pcap_ts).isoformat(),
                                "duration_ms": (current_silence_samples // ch) / sr * 1000
                            })
                
                current_silence_samples = 0
                
                # Optional: check if the end part of the chunk is zero (for stricter verification).
                # Here, we simplify by focusing on complete silence chunks or long continuous silences.
                
            total_samples_processed += chunk_size

        # Handling if silence continues at the end of the stream
        if current_silence_samples >= silence_threshold_samples:
            start_silence_idx = total_samples_processed - current_silence_samples
            rel_sec = (start_silence_idx // ch) / sr
            if len(silence_events) < 50:
                end_pcap_ts = first_pcap_ts + rel_sec if first_pcap_ts else 0
                silence_events.append({
                    "rel_sec": rel_sec,
                    "pcap_ts": end_pcap_ts,
                    "abs_time": datetime.fromtimestamp(end_pcap_ts).isoformat() if end_pcap_ts else "N/A",
                    "duration_ms": (current_silence_samples // ch) / sr * 1000
                })

        total_clips = sum(e["count"] for e in clip_events)
        total_silences = len(silence_events)
        
        status = "OK"
        msg = "Perfect"
        if total_silences > 0 and total_clips > 0:
            status = "CRIT"
            msg = f"{total_silences} Drop, {total_clips} Clip"
        elif total_silences > 0:
            status = "CRIT"
            msg = f"{total_silences} Silence Drop(s)"
        elif total_clips > 0:
            status = "WARN"
            msg = f"{total_clips} Clips Detected"

        stream.stats["payload_health"] = {
            "status": status,
            "msg": msg,
            "clip_events": clip_events,
            "silence_events": silence_events
        }
