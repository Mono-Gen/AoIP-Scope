import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.panel import Panel

class ConsoleManager:
    def __init__(self):
        # Configuration to prevent encoding issues in Windows environments
        self.console = Console(legacy_windows=True) if os.name == 'nt' else Console()
        
        # Determine a safe spinner based on console encoding (avoid Braille dots on CP932)
        encoding = getattr(self.console, "encoding", "utf-8")
        if encoding:
            encoding = encoding.lower()
        else:
            encoding = "utf-8"
        self.safe_spinner = "dots" if "utf" in encoding or "u8" in encoding else "line"
        self.safe_warn_icon = "⚠️" if "utf" in encoding or "u8" in encoding else "[!]"

    def print_banner(self, version: str):
        self.console.print(Panel.fit(
            f"[bold cyan]AoIP-Scope CLI[/bold cyan] v{version}\n[dim]Professional AES67 Diagnostic Tool[/dim]", 
            border_style="blue"
        ))

    def print_info(self, text: str):
        self.console.print(f"[dim]{text}[/dim]")

    def print_error(self, text: str):
        self.console.print(f"[red]Error: {text}[/red]")

    def print_warning(self, text: str):
        self.console.print(f"[yellow]{text}[/yellow]")

    def get_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(self.safe_spinner),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=self.console
        )

    def show_stream_table(self, analyzer):
        streams = analyzer.streams
        ptp_report = analyzer.ptp.get_report()
        
        # 1. Active RTP Streams Table (if any)
        if streams:
            table = Table(title="Active Audio Stream Inventory", border_style="dim", title_style="bold underline", show_lines=True)
            table.add_column("SSRC / Protocol", style="cyan", no_wrap=True)
            table.add_column("Source IP / Name", style="magenta", no_wrap=True)
            table.add_column("Dest IP:Port", style="magenta", no_wrap=True)
            table.add_column("Format", style="green", no_wrap=True)
            table.add_column("QoS (DSCP)", justify="center")
            table.add_column("Jitter (ms)", justify="right")
            table.add_column("Bandwidth", justify="right")
            table.add_column("Pkts", justify="right")
            table.add_column("Errs", justify="right", style="red")
            table.add_column("Payload Health", style="white")

            for ssrc, stream in streams.items():
                meta = stream.metadata
                vlan_str = f"\n[dim]VLAN: {meta.vlan_id}[/dim]" if meta.vlan_id else ""
                
                fmt_str = "[dim]Unknown[/dim]"
                if meta.encoding:
                    sr_str = f"{meta.sample_rate}"
                    if getattr(meta, 'is_heuristic', False):
                        sr_str += "* (Inferred)"
                    fmt_str = f"{meta.encoding}/{sr_str}/{meta.channels}\n({meta.ptime:.1f}ms, PT:{meta.payload_type})"
                
                dscp_label = str(meta.dscp)
                if meta.dscp == 46: dscp_label = "[bold red]46 (EF)[/bold red]"
                elif meta.dscp == 34: dscp_label = "[bold yellow]34 (AF41)[/bold yellow]"
                elif meta.dscp == 56: dscp_label = "[bold magenta]56 (CS7)[/bold magenta]"
                
                if not meta.qos_compliant:
                    dscp_label = f"[bold red]{self.safe_warn_icon} {meta.dscp}[/bold red]\n[dim red]Non-std[/dim red]"

                max_jitter_ms = stream.stats['max_jitter'] * 1000
                jitter_style = "green" if max_jitter_ms < 2.0 else "yellow" if max_jitter_ms < 5.0 else "red"

                name_str = f"\n[dim]{meta.session_name}[/dim]" if meta.session_name else f"\n[dim]{meta.src_mac}[/dim]"
                src_info = f"{meta.src_ip}{name_str}"
                
                ph = stream.stats.get("payload_health", {"status": "OK", "msg": "Not Analyzed"})
                if ph["status"] == "CRIT":
                    ph_str = f"[bold red][CRIT] {ph['msg']}[/bold red]"
                elif ph["status"] == "WARN":
                    ph_str = f"[bold yellow][WARN] {ph['msg']}[/bold yellow]"
                elif ph["status"] == "SKIP":
                    ph_str = f"[dim]{ph['msg']}[/dim]"
                else:
                    ph_str = f"[green][OK] {ph['msg']}[/green]"
                
                pps = stream.stats.get("avg_packet_rate_pps", 0.0)
                mbps = stream.stats.get("avg_bandwidth_mbps", 0.0)
                bw_str = f"{pps:,.1f} pps\n({mbps:.3f} Mbps)"

                table.add_row(
                    f"0x{ssrc:08X}\n[dim]{meta.protocol}[/dim]{vlan_str}",
                    src_info,
                    f"{meta.dst_ip}:{meta.dst_port}",
                    fmt_str,
                    dscp_label,
                    f"[{jitter_style}]{max_jitter_ms:.2f}[/]",
                    bw_str,
                    f"{len(stream.packets):,}",
                    str(sum(e["count"] for e in stream.error_log)),
                    ph_str
                )
            self.console.print(table)
            
            # QoS alerts detail
            qos_issues = []
            for ssrc, stream in streams.items():
                if not stream.metadata.qos_compliant:
                    for alert in stream.metadata.qos_alerts:
                        qos_issues.append(f"Stream 0x{ssrc:08X}: {alert}")
            if qos_issues:
                self.console.print(f"\n[bold yellow]{self.safe_warn_icon} QoS Configuration Issues Detected:[/bold yellow]")
                for issue in qos_issues:
                    self.console.print(f"  [red]- {issue}[/red]")
        else:
            self.console.print(Panel.fit(
                "[yellow]No active RTP audio streams captured (Non-mirror / Access port mode?)[/yellow]\n"
                "[dim]Audio traffic is restricted. Listing control plane discovery below.[/dim]",
                title="Active RTP Stream Inventory", border_style="yellow"
            ))

        # 2. mDNS / Dante Device Discovery Table
        dante_devices = analyzer.mdns.dante_devices
        if dante_devices:
            dev_table = Table(title="Discovered Dante & Network Devices", border_style="dim", title_style="bold underline")
            dev_table.add_column("IP Address", style="magenta")
            dev_table.add_column("Resolved Name", style="cyan")
            dev_table.add_column("Protocol / Type", style="green")

            for ip, info in sorted(dante_devices.items()):
                dev_table.add_row(ip, info["name"], info["type"])
            self.console.print(dev_table)

        # 3. SAP Advertised Streams Directory
        sap_configs = analyzer.sap_configs
        if sap_configs:
            sap_table = Table(title="SAP/SDP Stream Advertisements (AES67)", border_style="dim", title_style="bold underline")
            sap_table.add_column("Session Name", style="cyan")
            sap_table.add_column("Multicast Dest IP:Port", style="magenta")
            sap_table.add_column("Format", style="green")
            sap_table.add_column("PTP Clock Ref", style="yellow")

            for dst_ip, meta in sorted(sap_configs.items()):
                ptp_ref = meta.ts_refclk or 'N/A'
                fmt_str = f"{meta.encoding}/{meta.sample_rate}/{meta.channels} ({meta.ptime:.1f}ms)"
                sap_table.add_row(
                    meta.session_name,
                    f"{meta.dst_ip}:{meta.dst_port}",
                    fmt_str,
                    ptp_ref
                )
            self.console.print(sap_table)

        # PTP Status
        self.console.print(f"\n[bold]PTP Sync Status:[/bold] GM: [cyan]{ptp_report['current_gm']}[/cyan] | Changes: [yellow]{ptp_report['gm_changes_count']}[/yellow] | Health: {'[green]OK[/green]' if ptp_report['is_healthy'] else '[red]WARNING[/red]'}")
        
        # IGMP Status
        last_ts = max((s.packets[-1].pcap_ts for s in streams.values() if s.packets), default=0.0)
        igmp_report = analyzer.igmp.get_report(last_ts)
        self.console.print(f"\n[bold]IGMP & Network Health:[/bold]")
        self.console.print(f"Querier Status: {igmp_report['status_msg']}")
        if igmp_report['leave_events']:
            self.console.print(f"Leave Events  : {len(igmp_report['leave_events'])} Event(s) Detected")
            for e in igmp_report['leave_events'][:5]:
                self.console.print(f"  - {e['src_ip']} sent {e['type']} for {e['group_ip']} (at {e['ts']:.2f}s)")
        else:
            self.console.print(f"Leave Events  : [green]None[/green]")

    def show_interface_list(self, interfaces):
        table = Table(title="Available Network Interfaces", border_style="dim", title_style="bold underline")
        table.add_column("Index", style="cyan", justify="right")
        table.add_column("Interface Name / Description", style="green")
        table.add_column("IP Address", style="magenta")
        table.add_column("MAC Address", style="yellow")
        
        for idx, iface in enumerate(interfaces, 1):
            desc = iface["description"] if iface["description"] else "No description"
            name_str = f"[bold]{iface['name']}[/bold]\n[dim]{desc}[/dim]"
            table.add_row(
                str(idx),
                name_str,
                iface["ip"] if iface["ip"] else "[dim]N/A[/dim]",
                iface["mac"] if iface["mac"] else "[dim]N/A[/dim]"
            )
        self.console.print(table)

    def status(self, text: str):
        return self.console.status(text, spinner=self.safe_spinner)
