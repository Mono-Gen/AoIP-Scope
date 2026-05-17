import sys
import os
import argparse
from .engine.pcap_analyzer import PcapAnalyzer

def main():
    parser = argparse.ArgumentParser(description="AES67 PCAP Analyzer CLI")
    parser.add_argument("pcap", help="Path to the PCAP file")
    parser.add_argument("--sdp", help="Path to an external SDP file", default=None)
    
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"Error: File not found: {args.pcap}")
        return

    print(f"Analyzing {args.pcap}...")
    analyzer = PcapAnalyzer(args.pcap)
    analyzer.run()

    # Display PTP Sync Report (Step 2.2)
    ptp_report = analyzer.ptp.get_report()
    print("\n--- PTP Sync Status ---")
    print(f"  Grandmaster:  {ptp_report['current_gm']}")
    print(f"  GM Changes:   {ptp_report['gm_changes_count']}")
    print(f"  Sync Interval: {ptp_report['avg_sync_interval_ms']} ms", end="")
    if ptp_report["is_healthy"]:
        print(" (Healthy)")
    else:
        print(" (Warning: Unstable or Missing)")

    if args.sdp:
        if os.path.exists(args.sdp):
            print(f"Applying external SDP: {args.sdp}")
            if analyzer.apply_external_sdp(args.sdp):
                print("  SDP applied successfully.")
            else:
                print("  Warning: No matching stream found for the provided SDP.")
        else:
            print(f"Error: SDP file not found: {args.sdp}")

    print("\n--- Stream Discovery Results ---")
    if not analyzer.streams:
        print("No RTP streams found.")
        return

    for ssrc, stream in analyzer.streams.items():
        meta = stream.metadata
        print(f"SSRC: 0x{ssrc:08X}")
        print(f"  Name:     {meta.session_name or 'N/A'}")
        print(f"  Protocol: {meta.protocol}")
        print(f"  Source:   {meta.src_ip}")
        print(f"  Dest:     {meta.dst_ip}:{meta.dst_port}")
        print(f"  Format:   {meta.encoding} / {meta.sample_rate}Hz / {meta.channels}ch")
        print(f"  Packets:  {len(stream.packets)}")
        
        if stream.error_log:
            print(f"  Errors:   {len(stream.error_log)} detected")
            for err in stream.error_log[:5]:
                if err["type"] == "LOSS":
                    print(f"    [LOSS] count={err['count']}, seq={err['seq_missing']}")
                else:
                    print(f"    [{err['type']}] seq={err.get('seq')}")
        else:
            print("  Errors:   None")
        
        # Export Audio (Step 1.3)
        try:
            from .engine.audio_engine import AudioEngine
            payloads = analyzer.load_payloads(ssrc)
            wav_bytes = AudioEngine.generate_wav_with_timing(
                payloads, 
                stream.metadata.channels, 
                stream.metadata.sample_rate,
                ptime=getattr(stream.metadata, 'ptime', 1.0)
            )
            wav_name = f"stream_{ssrc:08X}.wav"
            with open(wav_name, "wb") as f:
                f.write(wav_bytes)
            print(f"  Audio:    Saved to {wav_name}")
        except Exception as e:
            print(f"  Audio:    Export failed ({e})")
        print("-" * 30)

if __name__ == "__main__":
    main()
