import socket
import struct
from typing import List, Dict

class IGMPAnalyzer:
    def __init__(self):
        self.last_query_ts: float = 0.0
        self.first_packet_ts: float = 0.0
        # List of {"ts": float, "src_ip": str, "group_ip": str, "type": str}
        self.leave_events: List[dict] = []

    def process_packet(self, ts: float, src_ip: bytes, igmp_data: bytes):
        if not igmp_data: return
        if self.first_packet_ts == 0.0:
            self.first_packet_ts = ts
            
        igmp_type = igmp_data[0]
        ip_str = socket.inet_ntoa(src_ip)
        
        # 0x11 = Membership Query
        if igmp_type == 0x11:
            self.last_query_ts = ts
            
        # 0x17 = IGMPv2 Leave Group
        elif igmp_type == 0x17:
            if len(igmp_data) >= 8:
                group_ip = socket.inet_ntoa(igmp_data[4:8])
                self.leave_events.append({
                    "ts": ts,
                    "src_ip": ip_str,
                    "group_ip": group_ip,
                    "type": "IGMPv2 Leave"
                })
                
        # 0x22 = IGMPv3 Membership Report
        elif igmp_type == 0x22:
            if len(igmp_data) >= 8:
                num_records = struct.unpack(">H", igmp_data[6:8])[0]
                offset = 8
                for _ in range(num_records):
                    if offset + 8 > len(igmp_data): break
                    record_type = igmp_data[offset]
                    aux_data_len = igmp_data[offset + 1]  # RFC 3376 §4.2.12: Aux Data Len (32bit words)
                    num_sources = struct.unpack(">H", igmp_data[offset+2:offset+4])[0]
                    group_ip = socket.inet_ntoa(igmp_data[offset+4:offset+8])
                    
                    # Type 3 = CHANGE_TO_INCLUDE_MODE (often used for leave in IGMPv3 if sources=0)
                    # Type 4 = CHANGE_TO_EXCLUDE_MODE
                    # Type 6 = BLOCK_OLD_SOURCES
                    if record_type == 3 and num_sources == 0:
                        self.leave_events.append({
                            "ts": ts,
                            "src_ip": ip_str,
                            "group_ip": group_ip,
                            "type": "IGMPv3 Leave (Include 0)"
                        })
                    offset += 8 + (num_sources * 4) + (aux_data_len * 4)  # RFC 3376 §4.2.12

    def get_report(self, current_ts: float) -> dict:
        is_healthy = True
        msg = "OK"
        if self.last_query_ts == 0.0:
            time_since_start = current_ts - self.first_packet_ts
            if time_since_start > 120.0: # If we've captured for 2 minutes without a query
                is_healthy = False
                msg = f"[CRITICAL] No IGMP Querier found in {time_since_start:.1f} seconds of capture!"
            else:
                msg = "[WARN] No IGMP Querier found yet (capture might be too short)"
        else:
            time_since_last = current_ts - self.last_query_ts
            if time_since_last > 260.0:
                is_healthy = False
                msg = f"[CRITICAL] IGMP Querier timeout! Last query was {time_since_last:.1f} seconds ago."
                
        return {
            "is_healthy": is_healthy,
            "status_msg": msg,
            "leave_events": self.leave_events
        }
