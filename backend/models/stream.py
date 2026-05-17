from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class StreamMetadata:
    ssrc: int
    src_ip: str
    dst_ip: str
    dst_port: int
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    protocol: str = "Unknown"
    session_name: Optional[str] = None
    encoding: str = "L24"
    sample_rate: int = 48000
    channels: int = 8
    ptime: float = 1.0
    payload_type: int = 96
    vlan_id: Optional[int] = None
    dscp: int = 0
    ttl: int = 0
    clock_domain: Optional[int] = None
    ts_refclk: Optional[str] = None  # PTP Master ID from SDP
    mediaclk: Optional[str] = None
    is_heuristic: bool = False

@dataclass
class PacketInfo:
    seq: int
    rtp_ts: int
    pcap_ts: float
    payload_offset: int = 0
    payload_len: int = 0
    status: str = "OK"  # OK, LOSS, OOO, DUP
    jitter: float = 0.0
    arrival_diff: float = 0.0 # Time since last packet

@dataclass
class AudioStream:
    metadata: StreamMetadata
    packets: List[PacketInfo] = field(default_factory=list)
    error_log: List[dict] = field(default_factory=list)
    stats: Dict = field(default_factory=lambda: {
        "max_jitter": 0.0,
        "avg_jitter": 0.0,
        "min_ttl": 255,
        "max_ttl": 0
    })
