import os
import sys
import argparse
from typing import List, Dict

# Add project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from backend.engine.pcap_analyzer import PcapAnalyzer
from backend.engine.audio_engine import AudioEngine
from backend.ui.console_manager import ConsoleManager
from backend.engine.report_generator import ReportGenerator
from backend.engine.live_capture import LiveCapture

class AoIPScopeCLI:
    VERSION = "0.9.5"

    def __init__(self):
        # Auto-widening terminal on Windows to prevent Rich table truncation
        import platform
        if platform.system() == "Windows":
            import os
            os.system('mode con: cols=140 lines=45')

        self.ui = ConsoleManager()
        self.parser = argparse.ArgumentParser(description="AoIP-Scope: Professional AES67/ST2110 Diagnostic CLI")
        self.setup_args()

    def setup_args(self):
        subparsers = self.parser.add_subparsers(dest="command", help="Subcommand to execute")

        # 1. 'analyze' subcommand
        parser_analyze = subparsers.add_parser("analyze", help="Analyze offline PCAP/PCAPNG file")
        parser_analyze.add_argument("pcap", help="Path to PCAP/PCAPNG file")
        parser_analyze.add_argument("--list", action="store_true", help="Just list streams and exit")
        parser_analyze.add_argument("--ssrc", help="Target SSRC (hex, e.g., 0x12345678)")
        parser_analyze.add_argument("--ch", help="Channels to extract (e.g., 1,2 or 5)", default=None)
        parser_analyze.add_argument("--mono", type=int, help="Extract a single channel as mono")
        parser_analyze.add_argument("--out", help="Output WAV filename")
        parser_analyze.add_argument("--report", action="store_true", help="Generate detailed JSON/Text report")
        parser_analyze.add_argument("--manual", action="store_true", help="Override metadata with manual params")
        parser_analyze.add_argument("--rate", type=int, default=48000, help="Manual sample rate (default: 48000)")
        parser_analyze.add_argument("--bits", type=int, choices=[16, 24], default=24, help="Manual bit depth (default: 24)")
        parser_analyze.add_argument("--ptime", type=float, default=1.0, help="Manual ptime in ms (default: 1.0)")

        # 2. 'record' subcommand
        parser_record = subparsers.add_parser("record", help="Live network packet capture")
        parser_record.add_argument("-i", "--interface", help="Network interface index or name (use 'ifaces' command to see list)")
        parser_record.add_argument("-o", "--out", default="capture.pcapng", help="Output PCAPNG filename (default: capture.pcapng)")
        parser_record.add_argument("-m", "--mode", choices=["mirror", "join"], default="mirror", help="Capture mode: mirror (passive) or join (active IGMP)")
        parser_record.add_argument("--ip", help="Multicast IP address to join (required in 'join' mode)")
        parser_record.add_argument("-t", "--duration", type=float, help="Capture duration in seconds (optional)")

        # 3. 'ifaces' subcommand
        parser_ifaces = subparsers.add_parser("ifaces", help="List available network interfaces")

    def run(self):
        sys_args = sys.argv[1:]
        
        # If no arguments are passed, start interactive mode (REPL)
        if not sys_args:
            self.run_interactive()
            return
            
        # Detect if launched via file drag-and-drop (single argument, not a command/flag)
        is_direct_run = False
        if len(sys_args) == 1 and sys_args[0] not in ["analyze", "record", "ifaces", "-h", "--help", "-v", "--version"]:
            is_direct_run = True
            sys_args.insert(0, "analyze")
            
        # Backwards compatibility: default to 'analyze' subcommand if not specified
        if sys_args and sys_args[0] not in ["analyze", "record", "ifaces", "-h", "--help", "-v", "--version"]:
            sys_args.insert(0, "analyze")
        
        try:
            args = self.parser.parse_args(sys_args)
            
            if not args.command:
                self.parser.print_help()
                return
    
            if args.command == "ifaces":
                self.run_ifaces()
            elif args.command == "record":
                self.run_record(args)
            elif args.command == "analyze":
                self.run_analyze(args)
        except SystemExit:
            # Trap SystemExit from --help or argument parsing errors to prevent instant closure
            pass
        finally:
            if is_direct_run:
                print("\n" + "=" * 50)
                input("Press [Enter] to exit...")

    def run_interactive(self):
        self.ui.print_banner(self.VERSION)
        print("Interactive mode started. Type 'help' or '?' for instructions, 'exit' or 'quit' to exit.")
        
        import shlex
        
        while True:
            try:
                cmd_line = input("\naoip-scope > ").strip()
                if not cmd_line:
                    continue
                
                # Using posix=False to support Windows backslashes in file paths correctly
                tokens = shlex.split(cmd_line, posix=False)
                if not tokens:
                    continue
                
                cmd = tokens[0].lower()
                
                if cmd in ["exit", "quit"]:
                    print("Exiting...")
                    break
                elif cmd in ["help", "?", "--help", "-h"]:
                    self.print_interactive_help()
                    continue
                
                try:
                    args = self.parser.parse_args(tokens)
                    if not args.command:
                        self.parser.print_help()
                        continue
                        
                    if args.command == "ifaces":
                        self.run_ifaces()
                    elif args.command == "record":
                        self.run_record(args)
                    elif args.command == "analyze":
                        self.run_analyze(args)
                except SystemExit:
                    # Trap argparse exit (e.g. --help or invalid args) and continue REPL
                    pass
                except Exception as e:
                    self.ui.print_error(f"Error executing command: {e}")
                    
            except (KeyboardInterrupt, EOFError):
                print("\nExiting...")
                break

    def print_interactive_help(self):
        print("\nAvailable Commands:")
        print("  analyze <pcap> [options] : Analyze offline PCAP/PCAPNG file")
        print("                             (e.g., analyze ./capture.pcapng --report)")
        print("  record [options]          : Live network packet capture")
        print("                             (e.g., record -i 1 -m join --ip 239.69.10.1)")
        print("  ifaces                    : List available network interfaces")
        print("  help, ?                   : Show this help message")
        print("  exit, quit                : Exit interactive mode")
        print("\nFor details on options for a specific command, use: <command> -h")
        print("  (e.g., analyze -h)")


    def run_ifaces(self):
        self.ui.print_banner(self.VERSION)
        interfaces = LiveCapture.list_interfaces()
        self.ui.show_interface_list(interfaces)

    def run_record(self, args):
        self.ui.print_banner(self.VERSION)
        interfaces = LiveCapture.list_interfaces()

        if not args.interface:
            self.ui.print_error("Please specify a network interface index or name using -i or --interface.")
            self.ui.show_interface_list(interfaces)
            return

        # Resolve interface by index or name
        target_iface = None
        try:
            idx = int(args.interface) - 1
            if 0 <= idx < len(interfaces):
                target_iface = interfaces[idx]["name"]
        except ValueError:
            # Match by name
            for iface in interfaces:
                if iface["name"].lower() == args.interface.lower() or iface["description"].lower() == args.interface.lower():
                    target_iface = iface["name"]
                    break

        if not target_iface:
            # Try passing the exact string to scapy directly as a last resort
            target_iface = args.interface

        if args.mode == "join" and not args.ip:
            self.ui.print_error("Error: Multicast IP address (--ip) is required in 'join' mode.")
            return

        # Start capturing
        try:
            capture = LiveCapture(
                interface=target_iface,
                output_file=args.out,
                mode=args.mode,
                multicast_ip=args.ip,
                progress_cb=lambda count: print(f"\rCaptured packets: {count:,}", end="", flush=True)
            )
            capture.start(duration=args.duration)
        except Exception as e:
            self.ui.print_error(f"Failed to start live capture: {e}")

    def run_analyze(self, args):
        if not os.path.exists(args.pcap):
            self.ui.print_error(f"File not found: {args.pcap}")
            return

        self.ui.print_banner(self.VERSION)
        self.ui.print_info(f"Input: {args.pcap}\n")

        # Analysis phase
        analyzer = None
        with self.ui.get_progress() as progress:
            task = progress.add_task("[cyan]Scanning PCAP...", total=100)
            
            def progress_cb(current, total):
                if total > 0:
                    progress.update(task, completed=(current / total) * 100)

            analyzer = PcapAnalyzer(args.pcap, progress_cb=progress_cb)
            analyzer.run()

        # Display stream list (including PTP, IGMP, and payload reports)
        self.ui.show_stream_table(analyzer)

        if not analyzer.streams:
            self.ui.print_warning("\nNo active RTP streams found. Control plane discovery finished.")
            return

        if args.list:
            return

        # Determine target SSRC
        target_ssrc = self._determine_target_ssrc(args, analyzer)

        # Report generation
        if args.report:
            report_file = ReportGenerator.generate(analyzer)
            self.ui.console.print(f"[bold cyan]Diagnostic report generated:[/bold cyan] [underline]{report_file}[/underline]")

        # Audio extraction
        if target_ssrc:
            self.extract_audio(analyzer, target_ssrc, args)

    def _determine_target_ssrc(self, args, analyzer):
        if args.ssrc:
            try:
                return int(args.ssrc, 16)
            except ValueError:
                self.ui.print_error(f"Invalid SSRC format: {args.ssrc}")
                return None
        elif len(analyzer.streams) == 1:
            return list(analyzer.streams.keys())[0]
        else:
            if not args.report:
                self.ui.print_warning("\nMultiple streams found. Please specify --ssrc <hex> to extract audio.")
            return None

    def extract_audio(self, analyzer, ssrc, args):
        if ssrc not in analyzer.streams:
            self.ui.print_error(f"SSRC 0x{ssrc:08X} not found.")
            return

        stream = analyzer.streams[ssrc]
        meta = stream.metadata
        
        encoding = "L24" if args.bits == 24 else "L16"
        sample_rate = args.rate
        channels = meta.channels if meta.channels else 2
        ptime = args.ptime
        
        if not args.manual and meta.encoding:
            encoding, sample_rate, channels, ptime = meta.encoding, meta.sample_rate, meta.channels, meta.ptime

        self.ui.console.print(f"\n[bold blue]Extracting Audio:[/bold blue] SSRC 0x{ssrc:08X} ({encoding}/{sample_rate}Hz/{channels}ch)")
        
        solo_ch = (args.mono - 1) if args.mono is not None else None
        ch_list = None
        
        if solo_ch is None and args.ch:
            try:
                ch_tokens = args.ch.split(',')
                ch_list = [int(tok.strip()) - 1 for tok in ch_tokens if tok.strip()]
            except ValueError:
                self.ui.print_error(f"Invalid channel format: {args.ch}. Use format like '3,4' or '5'.")
                return

        with self.ui.status("[bold green]Decoding and writing WAV..."):
            payloads = analyzer.load_payloads(ssrc)
            wav_bytes = AudioEngine.generate_wav_with_timing(
                payloads, channels, sample_rate, encoding=encoding, ptime=ptime, solo_ch=solo_ch, ch_list=ch_list
            )
            
            out_name = args.out if args.out else f"extract_{ssrc:08X}.wav"
            with open(out_name, "wb") as f:
                f.write(wav_bytes)
            
        # Display relative path instead of absolute path
        rel_path = os.path.relpath(out_name)
        self.ui.console.print(f"[bold green]Success![/bold green] Audio saved to: [underline]{rel_path}[/underline]")

if __name__ == "__main__":
    AoIPScopeCLI().run()
