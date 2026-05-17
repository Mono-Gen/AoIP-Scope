import os
import struct
from scapy.all import Ether, IP, UDP, wrpcap, DNS, DNSRR

# Helper function to create L24 RTP packet
def create_rtp_l24(seq, ts, payload, src_ip, dst_ip, src_port, dst_port, pt=97, ssrc=0x12345678):
    # Standard RTP header (12 bytes)
    # V=2 (10), P=0, X=0, CC=0 => 0x80
    # M=0, PT=97 => 0x61
    rtp_hdr = struct.pack(">BBHII", 0x80, pt, seq, ts, ssrc)
    return Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:01:01") / \
           IP(src=src_ip, dst=dst_ip) / \
           UDP(sport=src_port, dport=dst_port) / \
           (rtp_hdr + payload)

def generate_test_dante_mdns():
    print("Generating test_dante_mdns.pcap...")
    packets = []
    
    # 1. mDNS Packet (Dante device)
    # _netaudio-arc._udp PTR record
    mdns_req = Ether(dst="01:00:5E:00:00:FB")/IP(src="192.168.1.10", dst="224.0.0.251")/UDP(sport=5353, dport=5353)/ \
        DNS(id=0, qr=1, aa=1, rcode=0, 
            an=DNSRR(rrname="_netaudio-arc._udp.local.", type="PTR", rclass="IN", ttl=120, rdata="Dante-Mic-01._netaudio-arc._udp.local."))
    
    # Dante device IP mapping (A record)
    mdns_a = Ether(dst="01:00:5E:00:00:FB")/IP(src="192.168.1.10", dst="224.0.0.251")/UDP(sport=5353, dport=5353)/ \
        DNS(id=0, qr=1, aa=1, rcode=0, 
            an=DNSRR(rrname="Dante-Mic-01.local.", type="A", rclass="IN", ttl=120, rdata="192.168.1.10"))
    
    mdns_req.time = 0.0
    mdns_a.time = 0.1
    packets.extend([mdns_req, mdns_a])
    
    # 2. Dante Audio Packets (L24, 48kHz, 2ch) without SAP
    # Generate 50 packets to allow heuristic analyzer to work
    seq = 1000
    rtp_ts = 5000
    base_time = 1.0
    
    # 48kHz, 1ms ptime = 48 samples per channel = 96 samples total
    # L24 = 3 bytes per sample = 288 bytes payload
    payload = b'\x00\x00\x00' * 96
    
    for i in range(50):
        pkt = create_rtp_l24(seq, rtp_ts, payload, "192.168.1.10", "239.69.100.1", 4000, 4000, pt=96, ssrc=0xAABBCCDD)
        pkt.time = base_time + (i * 0.001)  # 1ms intervals
        packets.append(pkt)
        seq += 1
        rtp_ts += 48
        
    wrpcap("tests/test_dante_mdns.pcap", packets)

def generate_test_igmp_timeout():
    print("Generating test_igmp_timeout.pcap...")
    packets = []
    
    # Base RTP packets
    payload = b'\x00\x00\x00' * 96
    base_time = 0.0
    seq = 5000
    ts = 10000
    
    # Send some audio
    for i in range(200):
        pkt = create_rtp_l24(seq, ts, payload, "192.168.1.50", "239.69.100.2", 5000, 5000, pt=97, ssrc=0x99887766)
        pkt.time = base_time + (i * 0.001)
        packets.append(pkt)
        seq += 1
        ts += 48
    
    # IGMP Leave Group (0x17) from a receiver at t=0.15s
    # Note: Scapy's IGMP might be a bit raw. Protocol 2 is IGMP.
    # Type 0x17, Max Resp 0, Checksum, Group Address
    leave_payload = struct.pack(">BBH4s", 0x17, 0, 0, socket.inet_aton("239.69.100.2"))
    # Fix checksum
    leave_pkt = Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:02") / \
                IP(src="192.168.1.100", dst="224.0.0.2", proto=2, ttl=1) / \
                leave_payload
    leave_pkt.time = 0.15
    packets.append(leave_pkt)
    
    # No IGMP Queries (0x11) in the entire file. The last packet is at 0.2s. 
    # To trigger the "No Querier > 120s" logic, we need the pcap to span > 120s.
    pkt = create_rtp_l24(seq, ts, payload, "192.168.1.50", "239.69.100.2", 5000, 5000, pt=97, ssrc=0x99887766)
    pkt.time = 125.0
    packets.append(pkt)
    
    wrpcap("tests/test_igmp_timeout.pcap", packets)

import socket # needed for inet_aton
def generate_test_payload_errors():
    print("Generating test_payload_errors.pcap...")
    packets = []
    
    # 48kHz, 2ch, 1ms ptime
    base_time = 0.0
    seq = 100
    ts = 500
    
    # Packet 1: Normal Audio (0x010101)
    payload_normal = b'\x01\x01\x01' * 96
    
    # Packet 2: Silence (0x000000)
    payload_silence = b'\x00\x00\x00' * 96
    
    # Packet 3: Clipped Audio (0x7FFFFF)
    payload_clipped = b'\x7F\xFF\xFF' * 96
    
    for i in range(120): # 120 packets = 120ms
        if 20 <= i < 22:
            # 2ms of Clipping at ~20ms
            p = payload_clipped
        elif 50 <= i < 62:
            # 12ms of Silence at ~50ms
            p = payload_silence
        else:
            p = payload_normal
            
        pkt = create_rtp_l24(seq, ts, p, "192.168.1.60", "239.69.100.3", 6000, 6000, pt=97, ssrc=0x11223344)
        pkt.time = base_time + (i * 0.001)
        packets.append(pkt)
        seq += 1
        ts += 48
        
    wrpcap("tests/test_payload_errors.pcap", packets)

if __name__ == "__main__":
    generate_test_dante_mdns()
    generate_test_igmp_timeout()
    generate_test_payload_errors()
    print("All test PCAPs generated successfully.")
