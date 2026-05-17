import io
import wave
import numpy as np
from typing import List, Tuple

class AudioEngine:
    @staticmethod
    def decode_rtp(payload: bytes, num_channels: int, encoding: str = "L24") -> np.ndarray:
        """
        [Section 5-2 Extension] Decode L24 (24-bit) or L16 (16-bit) Big-Endian
        """
        if not payload:
            return np.zeros((num_channels, 0), dtype=np.int32)
            
        if encoding == "L24":
            raw = np.frombuffer(payload, dtype=np.uint8)
            valid_len = (len(raw) // 3) * 3
            raw = raw[:valid_len]
            num_samples_total = valid_len // 3
            if num_samples_total == 0: return np.zeros((num_channels, 0), dtype=np.int32)
            
            padded = np.zeros((num_samples_total, 4), dtype=np.uint8)
            padded[:, 1] = raw[0::3]
            padded[:, 2] = raw[1::3]
            padded[:, 3] = raw[2::3]
            
            samples_int32 = padded.view(np.int32).reshape(-1)
            samples_int32 = samples_int32.byteswap()
            
            mask = (samples_int32 >= 0x800000)
            samples_int32[mask] -= 0x1000000
            
            n_frames = num_samples_total // num_channels
            return samples_int32[:n_frames * num_channels].reshape(n_frames, num_channels).T
            
        elif encoding == "L16":
            # 16-bit Big-Endian -> int16
            samples_int16 = np.frombuffer(payload, dtype='>i2').astype(np.int32)
            num_samples_total = len(samples_int16)
            n_frames = num_samples_total // num_channels
            return samples_int16[:n_frames * num_channels].reshape(n_frames, num_channels).T
            
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    @staticmethod
    def generate_wav_with_timing(packet_data: List[Tuple[int, bytes]], num_channels: int, sample_rate: int, encoding: str = "L24", ptime: float = 1.0, solo_ch: int = None) -> bytes:
        """
        [Section 5-3 Compliant] Output WAV with timing correction and bit depth maintained
        """
        if not packet_data: return b""
        
        # NOTE: packet_data should already be in chronological order from PcapAnalyzer.
        # DO NOT sort by seq alone as it wraps around every 65536 packets.
        
        expected_samples_per_packet = int(sample_rate * (ptime / 1000.0))
        all_samples = []
        last_seq = packet_data[0][0] - 1

        for seq, payload in packet_data:
            gap = (seq - last_seq - 1) & 0xFFFF
            if 0 < gap < 1000:
                all_samples.append(np.zeros((num_channels, expected_samples_per_packet * gap), dtype=np.int32))
            
            samples = AudioEngine.decode_rtp(payload, num_channels, encoding)
            if samples.size > 0:
                all_samples.append(samples)
            last_seq = seq

        if not all_samples: return b""
        full_pcm = np.concatenate(all_samples, axis=1)

        if solo_ch is not None:
            idx = int(solo_ch)
            if 0 <= idx < full_pcm.shape[0]:
                full_pcm = full_pcm[idx : idx + 1, :]
            out_channels = 1
        else:
            out_channels = num_channels

        # Maintain output bit depth
        sampwidth = 3 if encoding == "L24" else 2
        
        with io.BytesIO() as wav_io:
            with wave.open(wav_io, 'wb') as ww:
                ww.setnchannels(out_channels)
                ww.setsampwidth(sampwidth)
                ww.setframerate(sample_rate)
                
                if encoding == "L24":
                    clipped = np.clip(full_pcm, -8388608, 8388607).astype(np.int32)
                    packed_bytes = clipped.T.flatten().tobytes()
                    res_bytes = bytearray()
                    for i in range(0, len(packed_bytes), 4):
                        res_bytes += packed_bytes[i:i+3]
                    ww.writeframes(bytes(res_bytes))
                else:
                    # L16
                    clipped = np.clip(full_pcm, -32768, 32767).astype(np.int16)
                    ww.writeframes(clipped.T.flatten().tobytes())
                    
            return wav_io.getvalue()

    @staticmethod
    def get_waveform_data_all_channels(packet_data: List[Tuple[int, bytes]], num_channels: int, sample_rate: int, encoding: str = "L24", ptime: float = 1.0, start_ts: float = 0, num_points: int = 2000):
        wav_binary = AudioEngine.generate_wav_with_timing(packet_data, num_channels, sample_rate, encoding, ptime)
        if not wav_binary: return {"channels": []}
        
        with io.BytesIO(wav_binary) as bio:
            with wave.open(bio, 'rb') as wr:
                n_frames = wr.getnframes()
                sampwidth = wr.getsampwidth()
                raw_bytes = wr.readframes(n_frames)
                
                if sampwidth == 3:
                    num_samples = len(raw_bytes) // 3
                    padded = np.zeros((num_samples, 4), dtype=np.uint8)
                    padded[:, 0:3] = np.frombuffer(raw_bytes, dtype=np.uint8).reshape(-1, 3)
                    pcm_data = padded.view(np.int32).reshape(n_frames, wr.getnchannels()).T
                    max_val = 8388608.0
                else:
                    pcm_data = np.frombuffer(raw_bytes, dtype=np.int16).reshape(n_frames, wr.getnchannels()).T
                    max_val = 32768.0
        
        total_frames = pcm_data.shape[1]
        step = max(1, total_frames // num_points)
        channels_data = []
        for ch in range(pcm_data.shape[0]):
            ch_pcm = pcm_data[ch]
            mins, maxs = [], []
            for i in range(0, total_frames, step):
                chunk = ch_pcm[i : i + step]
                if len(chunk) > 0:
                    mins.append(float(np.min(chunk)) / max_val)
                    maxs.append(float(np.max(chunk)) / max_val)
            channels_data.append({"min": mins, "max": maxs})

        return {
            "channels": channels_data,
            "total_samples": total_frames,
            "duration": total_frames / sample_rate,
            "start_ts": start_ts
        }
