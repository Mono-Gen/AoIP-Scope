import dpkt
import socket
from typing import Dict

class MDNSParser:
    def __init__(self):
        # Maps IP address (str) to dict: {"name": str, "type": str}
        self.dante_devices: Dict[str, Dict[str, str]] = {}

    def process_packet(self, src_ip: bytes, udp_data: bytes):
        try:
            dns = dpkt.dns.DNS(udp_data)
        except Exception:
            return

        ip_str = socket.inet_ntoa(src_ip)
        records = getattr(dns, 'an', []) or []
        records = list(records) + list(getattr(dns, 'ns', []) or []) + list(getattr(dns, 'ar', []) or [])

        dante_keywords = {'_netaudio', '_audinate', 'tio1608', 'dm3', 'brooklyn', 'bklyn', 'hbn', 'yamaha', 'dante'}

        for rr in records:
            # 1. Parse PTR, TXT, SRV records (Standard mDNS discovery)
            is_dante = False
            device_name = None
            resolved_ip = ip_str

            if rr.type == dpkt.dns.DNS_PTR:
                if getattr(rr, 'ptrname', ''):
                    ptr = rr.ptrname.lower()
                    if any(k in ptr for k in dante_keywords) or getattr(rr, 'name', '').lower().find('_netaudio') != -1:
                        is_dante = True
                        if ptr.endswith('._netaudio-arc._udp.local.'):
                            device_name = ptr.split('._netaudio-arc')[0]
                        elif ptr.endswith('._netaudio-cmc._udp.local.'):
                            device_name = ptr.split('._netaudio-cmc')[0]
                        elif ptr.endswith('._netaudio-arc._udp.local'):
                            device_name = ptr.split('._netaudio-arc')[0]
                        elif ptr.endswith('._netaudio-cmc._udp.local'):
                            device_name = ptr.split('._netaudio-cmc')[0]
                        else:
                            # Generic fallback for ptr
                            device_name = ptr.split('.')[0]
            
            elif rr.type == dpkt.dns.DNS_TXT:
                name = getattr(rr, 'name', '').lower()
                if any(k in name for k in dante_keywords):
                    is_dante = True
                    if '._netaudio' in name:
                        device_name = name.split('._netaudio')[0]
                    else:
                        device_name = name.split('.')[0]

            elif rr.type == dpkt.dns.DNS_SRV:
                name = getattr(rr, 'name', '').lower()
                if any(k in name for k in dante_keywords):
                    is_dante = True
                    if '._netaudio' in name:
                        device_name = name.split('._netaudio')[0]
                    else:
                        device_name = name.split('.')[0]

            # 2. Parse A records (IP mapping)
            elif rr.type == dpkt.dns.DNS_A:
                name = getattr(rr, 'name', '').lower()
                if name.endswith('.local.'): name = name[:-7]
                elif name.endswith('.local'): name = name[:-6]
                
                try:
                    resolved_ip = socket.inet_ntoa(rr.rdata)
                    device_name = name
                    is_dante = any(k in name for k in dante_keywords)
                except Exception:
                    continue

            # Save the discovered device
            if device_name and resolved_ip:
                # Clean name capitalization if it's a raw hostname
                clean_name = device_name.strip()
                if resolved_ip not in self.dante_devices or clean_name != "Unknown Dante Device":
                    dev_type = "Dante (mDNS)" if is_dante else "Device (mDNS)"
                    # Don't overwrite higher quality names with generic ones
                    if resolved_ip in self.dante_devices:
                        existing = self.dante_devices[resolved_ip]
                        if existing["type"] == "Dante (mDNS)" and dev_type == "Device (mDNS)":
                            continue
                    
                    self.dante_devices[resolved_ip] = {
                        "name": clean_name,
                        "type": dev_type
                    }
