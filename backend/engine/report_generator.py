import json
import os
from datetime import datetime
from typing import Dict

class ReportGenerator:
    VERSION = "0.9.2"

    @staticmethod
    def generate(analyzer, output_dir: str = ".") -> str:
        # Use filename only (avoiding absolute paths)
        pcap_filename = os.path.basename(analyzer.pcap_path)
        report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Determine overall PCAP capture time range from all stream packets
        all_timestamps = [
            p.pcap_ts
            for stream in analyzer.streams.values()
            for p in stream.packets
        ]
        capture_start = min(all_timestamps) if all_timestamps else None
        capture_end   = max(all_timestamps) if all_timestamps else None
        capture_duration = round(capture_end - capture_start, 3) if (capture_start and capture_end) else None

        # Current timestamp used for IGMP health check
        current_ts = capture_end or 0.0

        data = {
            "tool_version": ReportGenerator.VERSION,
            "pcap_file": pcap_filename,
            "report_timestamp": datetime.now().isoformat(),
            "capture_range": {
                "start_unix": round(capture_start, 6) if capture_start else None,
                "end_unix":   round(capture_end,   6) if capture_end   else None,
                "duration_sec": capture_duration
            },
            "ptp_analysis": analyzer.ptp.get_report(),
            "igmp_analysis": analyzer.igmp.get_report(current_ts),
            "mdns_devices": analyzer.mdns.dante_devices,
            "streams": {}
        }

        for ssrc, stream in analyzer.streams.items():
            m = stream.metadata
            packets = stream.packets

            # --- Packet loss summary ---
            total_lost = sum(e["count"] for e in stream.error_log)
            total_received = len(packets)
            total_expected = total_received + total_lost
            loss_rate_pct = round(total_lost / total_expected * 100, 3) if total_expected > 0 else 0.0

            # --- Jitter (average over all packets) ---
            jitter_values = [p.jitter for p in packets if p.jitter > 0]
            avg_jitter_ms = round((sum(jitter_values) / len(jitter_values)) * 1000, 3) if jitter_values else 0.0
            max_jitter_ms = round(stream.stats["max_jitter"] * 1000, 3)

            # --- Stream duration ---
            duration_sec = round(packets[-1].pcap_ts - packets[0].pcap_ts, 3) if len(packets) >= 2 else 0.0

            data["streams"][f"0x{ssrc:08X}"] = {
                "session_name": m.session_name,
                "protocol": m.protocol,
                "is_heuristic": m.is_heuristic,
                "network": {
                    "src_ip":  m.src_ip,  "src_mac": m.src_mac,
                    "dst_ip":  m.dst_ip,  "dst_mac": m.dst_mac,
                    "dst_port": m.dst_port,
                    "vlan_id": m.vlan_id,
                    "dscp":    m.dscp,
                    "min_ttl": stream.stats["min_ttl"],
                    "max_ttl": stream.stats["max_ttl"]
                },
                "format": {
                    "encoding":     m.encoding,
                    "sample_rate":  m.sample_rate,
                    "channels":     m.channels,
                    "ptime_ms":     m.ptime,
                    "payload_type": m.payload_type
                },
                "timing_sdp": {
                    "clock_domain": m.clock_domain,
                    "ts_refclk":    m.ts_refclk,
                    "mediaclk":     m.mediaclk
                },
                "stats": {
                    "packet_count":   total_received,
                    "loss_count":     total_lost,
                    "loss_rate_pct":  loss_rate_pct,
                    "avg_jitter_ms":  avg_jitter_ms,
                    "max_jitter_ms":  max_jitter_ms,
                    "duration_sec":   duration_sec
                },
                "payload_health": stream.stats.get("payload_health", {
                    "status": "SKIP",
                    "msg": "Not Analyzed",
                    "clip_events": [],
                    "silence_events": []
                }),
                "errors": stream.error_log
            }

        target_path = os.path.join(output_dir, report_name)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return report_name

