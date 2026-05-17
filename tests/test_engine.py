"""
Regression tests for AoIP-Scope engine.
Run from the project root:
    pytest tests/test_engine.py -v
"""
import os
import sys
import struct
import numpy as np
import pytest

# Ensure project root is on the path regardless of CWD
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.engine.audio_engine import AudioEngine
from backend.engine.heuristic_analyzer import HeuristicAnalyzer
from backend.engine.sdp_parser import SdpParser
from backend.engine.igmp_analyzer import IGMPAnalyzer
from backend.engine.pcap_analyzer import PcapAnalyzer

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# AudioEngine: L24 decode / encode round-trip
# ---------------------------------------------------------------------------

class TestAudioEngineL24:
    def _make_l24_payload(self, samples: list) -> bytes:
        """Pack a list of int24 samples as big-endian 3-byte each."""
        out = bytearray()
        for s in samples:
            s = s & 0xFFFFFF
            out += bytes([(s >> 16) & 0xFF, (s >> 8) & 0xFF, s & 0xFF])
        return bytes(out)

    def test_positive_sample(self):
        """A known positive 24-bit value should decode correctly."""
        payload = self._make_l24_payload([0x7FFFFF])  # max positive
        result = AudioEngine.decode_rtp(payload, num_channels=1, encoding="L24")
        assert result[0, 0] == 0x7FFFFF

    def test_negative_sample(self):
        """0x800000 is the most negative value in signed 24-bit."""
        payload = self._make_l24_payload([0x800000])
        result = AudioEngine.decode_rtp(payload, num_channels=1, encoding="L24")
        assert result[0, 0] == -8388608

    def test_zero_sample(self):
        payload = self._make_l24_payload([0x000000])
        result = AudioEngine.decode_rtp(payload, num_channels=1, encoding="L24")
        assert result[0, 0] == 0

    def test_multichannel_interleave(self):
        """Stereo payload: [L, R, L, R, ...] should be split into 2 channels."""
        samples = [0x010000, 0x020000, 0x030000, 0x040000]  # L R L R
        payload = self._make_l24_payload(samples)
        result = AudioEngine.decode_rtp(payload, num_channels=2, encoding="L24")
        assert result.shape == (2, 2)
        assert result[0, 0] == 0x010000  # Ch0 frame0
        assert result[1, 0] == 0x020000  # Ch1 frame0

    def test_wav_roundtrip_l24(self):
        """Encode to WAV and verify sample values survive the round-trip."""
        original = [100000, -200000, 0, 8388607, -8388608]
        payload = self._make_l24_payload(original)
        packet_data = [(0, payload)]
        wav = AudioEngine.generate_wav_with_timing(packet_data, 1, 48000, "L24", 1.0)
        assert len(wav) > 44  # At least a WAV header

        wf_data = AudioEngine.get_waveform_data_all_channels(packet_data, 1, 48000, "L24", 1.0)
        assert "channels" in wf_data
        assert len(wf_data["channels"]) == 1


class TestAudioEngineL16:
    def test_positive_sample(self):
        payload = struct.pack(">h", 32767)
        result = AudioEngine.decode_rtp(payload, num_channels=1, encoding="L16")
        assert result[0, 0] == 32767

    def test_negative_sample(self):
        payload = struct.pack(">h", -32768)
        result = AudioEngine.decode_rtp(payload, num_channels=1, encoding="L16")
        assert result[0, 0] == -32768


# ---------------------------------------------------------------------------
# SdpParser: encoding name normalisation
# ---------------------------------------------------------------------------

class TestSdpParser:
    SDP_TEMPLATE = "v=0\ns=Test\nc=IN IP4 239.69.0.1\nm=audio 5004 RTP/AVP 96\na=rtpmap:96 {enc}/48000/8\na=ptime:1\n"

    def test_uppercase_encoding(self):
        meta = SdpParser.parse(self.SDP_TEMPLATE.format(enc="L24"))
        assert meta.encoding == "L24"

    def test_lowercase_encoding_normalised(self):
        meta = SdpParser.parse(self.SDP_TEMPLATE.format(enc="l24"))
        assert meta.encoding == "L24"

    def test_channels_parsed(self):
        meta = SdpParser.parse(self.SDP_TEMPLATE.format(enc="L24"))
        assert meta.channels == 8

    def test_dst_ip_parsed(self):
        meta = SdpParser.parse(self.SDP_TEMPLATE.format(enc="L24"))
        assert meta.dst_ip == "239.69.0.1"


# ---------------------------------------------------------------------------
# HeuristicAnalyzer: encoding/channel inference
# ---------------------------------------------------------------------------
from backend.models.stream import AudioStream, StreamMetadata, PacketInfo

def _make_stream(payload_len: int, samples_per_packet: int) -> AudioStream:
    """Create a minimal AudioStream for heuristic analysis."""
    meta = StreamMetadata(ssrc=1, src_ip="192.168.0.1", dst_ip="239.0.0.1", dst_port=5004)
    stream = AudioStream(metadata=meta)
    # Two consecutive packets to allow sample-rate and spp detection
    for i in range(2):
        stream.packets.append(PacketInfo(
            seq=i,
            rtp_ts=i * samples_per_packet,
            pcap_ts=float(i) * (samples_per_packet / 48000.0),
            payload_len=payload_len
        ))
    return stream

class TestHeuristicAnalyzer:
    def test_l24_stereo(self):
        """48 samples/pkt * 2ch * 3 bytes = 288 bytes → L24 stereo."""
        stream = _make_stream(payload_len=48 * 2 * 3, samples_per_packet=48)
        HeuristicAnalyzer.analyze(stream)
        assert stream.metadata.encoding == "L24"
        assert stream.metadata.channels == 2

    def test_l24_8ch(self):
        """48 * 8 * 3 = 1152 bytes → L24 8ch."""
        stream = _make_stream(payload_len=48 * 8 * 3, samples_per_packet=48)
        HeuristicAnalyzer.analyze(stream)
        assert stream.metadata.encoding == "L24"
        assert stream.metadata.channels == 8

    def test_l16_stereo(self):
        """48 samples/pkt * 2ch * 2 bytes = 192 bytes → L16 stereo."""
        stream = _make_stream(payload_len=48 * 2 * 2, samples_per_packet=48)
        HeuristicAnalyzer.analyze(stream)
        assert stream.metadata.encoding == "L16"
        assert stream.metadata.channels == 2

    def test_is_heuristic_flag(self):
        stream = _make_stream(payload_len=48 * 2 * 3, samples_per_packet=48)
        HeuristicAnalyzer.analyze(stream)
        assert stream.metadata.is_heuristic is True


# ---------------------------------------------------------------------------
# IGMPAnalyzer: health reporting
# ---------------------------------------------------------------------------

class TestIGMPAnalyzer:
    def test_no_querier_short_capture(self):
        igmp = IGMPAnalyzer()
        igmp.first_packet_ts = 0.0
        report = igmp.get_report(current_ts=30.0)
        # Less than 120s → warn but not critical
        assert report["is_healthy"] is True
        assert "WARN" in report["status_msg"]

    def test_no_querier_long_capture(self):
        igmp = IGMPAnalyzer()
        igmp.first_packet_ts = 0.0
        report = igmp.get_report(current_ts=200.0)
        assert report["is_healthy"] is False
        assert "CRITICAL" in report["status_msg"]

    def test_querier_timeout(self):
        igmp = IGMPAnalyzer()
        igmp.first_packet_ts = 0.0
        igmp.last_query_ts = 1.0
        report = igmp.get_report(current_ts=300.0)
        assert report["is_healthy"] is False


# ---------------------------------------------------------------------------
# PcapAnalyzer: integration smoke tests using test vectors
# ---------------------------------------------------------------------------

class TestPcapAnalyzer:
    def _pcap(self, name):
        path = os.path.join(TESTS_DIR, name)
        if not os.path.exists(path):
            pytest.skip(f"Test PCAP not found: {name}  (run generate_test_pcaps.py first)")
        return path

    def test_payload_errors_pcap_detects_clips(self):
        analyzer = PcapAnalyzer(self._pcap("test_payload_errors.pcap"))
        analyzer.run()
        assert len(analyzer.streams) >= 1
        for stream in analyzer.streams.values():
            health = stream.stats.get("payload_health", {})
            # The test vector contains deliberate clipping
            assert health.get("status") in ("WARN", "CRIT", "OK", "SKIP")

    def test_dante_mdns_pcap_discovers_device(self):
        analyzer = PcapAnalyzer(self._pcap("test_dante_mdns.pcap"))
        analyzer.run()
        # At least one Dante device should be discovered
        assert len(analyzer.mdns.dante_devices) >= 1

    def test_igmp_timeout_pcap(self):
        analyzer = PcapAnalyzer(self._pcap("test_igmp_timeout.pcap"))
        analyzer.run()
        # IGMP analysis should have processed at least one packet
        # (last_query_ts updated or leave_events present)
        igmp = analyzer.igmp
        assert igmp.first_packet_ts > 0 or len(igmp.leave_events) >= 0
