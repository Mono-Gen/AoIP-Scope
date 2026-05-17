import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class PTPSyncStatus:
    current_gm: str = "Unknown"
    gm_changes: List[dict] = field(default_factory=list)
    sync_intervals: List[float] = field(default_factory=list)
    last_sync_ts: float = 0.0
    domain_number: int = 0
    gm_priority1: int = 255
    gm_priority2: int = 255
    gm_clock_class: int = 255
    gm_clock_accuracy: int = 0xFE # Unknown

class PTPAnalyzer:
    def __init__(self):
        self.status = PTPSyncStatus()

    def process_packet(self, pcap_ts: float, data: bytes):
        """PTP v2メッセージの深層パース (IEEE 1588-2008)"""
        if len(data) < 34: return
        
        # PTP Header (34 bytes)
        msg_type = data[0] & 0x0F
        self.status.domain_number = data[4]
        
        if msg_type == 0:  # Sync
            if self.status.last_sync_ts > 0:
                interval = (pcap_ts - self.status.last_sync_ts) * 1000 # ms
                if interval < 2000:
                    self.status.sync_intervals.append(interval)
            self.status.last_sync_ts = pcap_ts

        elif msg_type == 11:  # Announce
            # Announce Body starts at offset 34
            # 34-43: originTimestamp (10)
            # 44-45: currentUtcOffset (2)
            # 46: reserved (1)
            # 47: gmPriority1 (1)
            # 48-51: gmClockQuality (4)
            # 52: gmPriority2 (1)
            # 53-60: gmIdentity (8)
            if len(data) >= 61:
                self.status.gm_priority1 = data[47]
                self.status.gm_clock_class = data[48]
                self.status.gm_clock_accuracy = data[49]
                self.status.gm_priority2 = data[52]
                
                gm_id = data[53:61].hex(':')
                if self.status.current_gm != gm_id:
                    if self.status.current_gm != "Unknown":
                        self.status.gm_changes.append({
                            "ts": pcap_ts,
                            "old": self.status.current_gm,
                            "new": gm_id
                        })
                    self.status.current_gm = gm_id

    def get_report(self) -> dict:
        intervals = self.status.sync_intervals
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        
        is_healthy = True
        if intervals and not (80 <= avg_interval <= 160):
            is_healthy = False
        if self.status.domain_number != 0:
            is_healthy = False

        return {
            "current_gm": self.status.current_gm,
            "domain": self.status.domain_number,
            "gm_priority1": self.status.gm_priority1,
            "gm_priority2": self.status.gm_priority2,
            "gm_clock_class": self.status.gm_clock_class,
            "gm_clock_accuracy": hex(self.status.gm_clock_accuracy),
            "gm_changes_count": len(self.status.gm_changes),
            "avg_sync_interval_ms": round(avg_interval, 2),
            "is_healthy": is_healthy
        }
