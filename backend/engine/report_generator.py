import json
import os
from datetime import datetime
from typing import Dict

class ReportGenerator:
    @staticmethod
    def generate(analyzer, output_dir: str = ".") -> str:
        # Use filename only (avoiding absolute paths)
        pcap_filename = os.path.basename(analyzer.pcap_path)
        report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        data = {
            "pcap_file": pcap_filename,
            "report_timestamp": datetime.now().isoformat(),
            "ptp_analysis": analyzer.ptp.get_report(),
            "streams": {}
        }
        
        for ssrc, stream in analyzer.streams.items():
            m = stream.metadata
            data["streams"][f"0x{ssrc:08X}"] = {
                "network": {
                    "src_ip": m.src_ip, "src_mac": m.src_mac,
                    "dst_ip": m.dst_ip, "dst_mac": m.dst_mac,
                    "dst_port": m.dst_port,
                    "vlan_id": m.vlan_id,
                    "dscp": m.dscp,
                    "ttl": m.ttl
                },
                "format": {
                    "encoding": m.encoding, "rate": m.sample_rate, 
                    "ch": m.channels, "ptime": m.ptime,
                    "payload_type": m.payload_type
                },
                "timing_sdp": {
                    "clock_domain": m.clock_domain,
                    "ts_refclk": m.ts_refclk,
                    "mediaclk": m.mediaclk
                },
                "stats": {
                    "packet_count": len(stream.packets),
                    "max_jitter_ms": round(stream.stats['max_jitter'] * 1000, 3)
                },
                "errors": stream.error_log
            }
            
        target_path = os.path.join(output_dir, report_name)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        return report_name
