import os
import sys
import time
import threading
import socket
import struct
from typing import Optional, Callable
from scapy.all import sniff, PcapWriter, get_working_ifaces, IP, sendp, Ether, IPOption_Router_Alert
from scapy.contrib.igmp import IGMP
from rich.console import Console

class LiveCapture:
    def __init__(self, 
                 interface: str, 
                 output_file: str = "capture.pcapng",
                 mode: str = "mirror", 
                 multicast_ip: Optional[str] = None,
                 progress_cb: Optional[Callable[[int], None]] = None):
        self.interface = interface
        self.output_file = output_file
        self.mode = mode
        self.multicast_ip = multicast_ip
        self.progress_cb = progress_cb
        self.stop_event = threading.Event()
        self.packet_count = 0
        self._igmp_socket = None
        self.console = Console()

    @staticmethod
    def list_interfaces():
        """Returns a list of working network interfaces."""
        interfaces = []
        try:
            for iface in get_working_ifaces():
                # On Windows, iface.name is often a friendly name, and iface.guid is the UUID
                interfaces.append({
                    "name": iface.name,
                    "description": iface.description,
                    "ip": iface.ip,
                    "mac": iface.mac,
                    "guid": iface.guid
                })
        except Exception as e:
            Console().print(f"[bold red]Error retrieving interfaces: {e}[/bold red]")
        return interfaces

    def _ip_to_multicast_mac(self, ip_str: str) -> str:
        """Converts an IP multicast address to its corresponding Ethernet MAC address."""
        try:
            parts = list(map(int, ip_str.split('.')))
            if len(parts) == 4:
                mac_bytes = [0x01, 0x00, 0x5e, parts[1] & 0x7f, parts[2], parts[3]]
                return ":".join(f"{b:02x}" for b in mac_bytes)
        except Exception:
            pass
        return "01:00:5e:00:00:01"

    def _join_multicast_group(self):
        """Sends an active IGMP Join (Membership Report) to trigger switch streaming."""
        if not self.multicast_ip:
            return

        try:
            # Construct standard-compliant IGMPv2 packet with Router Alert (RFC 2113)
            # Sent at Layer 2 (Ethernet) to bypass Windows link-local routing constraints
            dst_mac = self._ip_to_multicast_mac(self.multicast_ip)
            self.console.print(f"[bold green]Sending IGMPv2 Join for {self.multicast_ip} (MAC: {dst_mac})...[/bold green]")
            
            pkt = Ether(dst=dst_mac) / \
                  IP(dst=self.multicast_ip, ttl=1, options=[IPOption_Router_Alert()]) / \
                  IGMP(type=0x16, gaddr=self.multicast_ip)
                  
            sendp(pkt, iface=self.interface, verbose=False)
        except Exception as e:
            self.console.print(f"[bold yellow]Warning: Failed to send Scapy IGMP Join: {e}[/bold yellow]")

        # Also join via standard socket level to ensure the OS network stack accepts it
        try:
            # Create a UDP socket to join the group at OS level
            self._igmp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._igmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._igmp_socket.bind(('', 0))
            
            mreq = struct.pack("4s4s", socket.inet_aton(self.multicast_ip), socket.inet_aton("0.0.0.0"))
            self._igmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception:
            pass # Fallback to raw packet if socket join fails (common on non-admin/restricted interface)

    def _leave_multicast_group(self):
        """Sends an active IGMP Leave to clean up multicast routing."""
        if not self.multicast_ip:
            return

        try:
            # IGMPv2 Leave Group (Type 0x17) is sent to all-routers multicast group (224.0.0.2 / MAC 01:00:5e:00:00:02)
            dst_mac = "01:00:5e:00:00:02"
            self.console.print(f"\n[bold yellow]Sending IGMPv2 Leave for {self.multicast_ip}...[/bold yellow]")
            
            pkt = Ether(dst=dst_mac) / \
                  IP(dst="224.0.0.2", ttl=1, options=[IPOption_Router_Alert()]) / \
                  IGMP(type=0x17, gaddr=self.multicast_ip)
                  
            sendp(pkt, iface=self.interface, verbose=False)
        except Exception:
            pass

        if self._igmp_socket:
            try:
                mreq = struct.pack("4s4s", socket.inet_aton(self.multicast_ip), socket.inet_aton("0.0.0.0"))
                self._igmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                self._igmp_socket.close()
            except:
                pass

    def start(self, duration: Optional[float] = None):
        """Starts capturing packets and streaming them to PCAP file."""
        # Ensure output directory exists
        out_dir = os.path.dirname(self.output_file)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        writer = PcapWriter(self.output_file, append=False, sync=True)
        
        if self.mode == "join" and self.multicast_ip:
            self._join_multicast_group()

        self.console.print(f"[bold cyan]Recording started on interface '{self.interface}'...[/bold cyan]")
        self.console.print(f"[dim]Saving packets directly to: {self.output_file}[/dim]")
        self.console.print("[yellow]Press Ctrl+C to stop recording.[/yellow]")

        def packet_handler(pkt):
            writer.write(pkt)
            self.packet_count += 1
            if self.progress_cb:
                self.progress_cb(self.packet_count)

        start_time = time.time()
        
        def stop_filter(pkt):
            if self.stop_event.is_set():
                return True
            if duration and (time.time() - start_time) >= duration:
                return True
            return False

        try:
            # We run sniff in the current thread
            # store=0 prevents Scapy from keeping packets in memory, ensuring memory safety!
            sniff(iface=self.interface, prn=packet_handler, stop_filter=stop_filter, store=0)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.console.print(f"[bold red]Error during packet sniffing: {e}[/bold red]")
        finally:
            writer.close()
            if self.mode == "join" and self.multicast_ip:
                self._leave_multicast_group()
            self.console.print(f"\n[bold green]Recording stopped. Total packets captured: {self.packet_count:,}[/bold green]")

    def stop(self):
        """Triggers stop of capture loop."""
        self.stop_event.set()
