"""
Safe Synthetic PCAP Generator for Network Intrusion Detection System (NIDS).
Generates harmless synthetic network packets simulating:
1. Normal baseline traffic (HTTP, HTTPS, DNS, NTP).
2. Port Scan attack pattern (25 distinct destination ports within 4 seconds).
3. Brute-Force connection attempt indicator (15 rapid connections to SSH port 22 within 20 seconds).
4. Traffic Flooding burst (120 rapid packets within 2 seconds).

This utility allows offline testing and demonstration without needing live network access,
packet injection tools, or administrative privileges.
"""

import os
import time
from typing import List

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap, Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def generate_synthetic_pcap(output_filepath: str) -> bool:
    """
    Generates a deterministic, harmless test PCAP file containing both normal traffic
    and multi-category attack indicators.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not installed. Cannot generate PCAP.")
        return False

    packets: List[Packet] = []
    base_time = 1700000000.0  # Stable synthetic timestamp

    # -------------------------------------------------------------
    # 1. Normal Baseline Traffic (HTTP, HTTPS, DNS)
    # -------------------------------------------------------------
    # Normal client browsing web
    normal_client = "192.168.1.20"
    web_server = "93.184.216.34"      # example.com
    dns_server = "8.8.8.8"

    for i in range(6):
        t = base_time + (i * 2.0)
        # DNS Query
        dns_pkt = IP(src=normal_client, dst=dns_server) / UDP(sport=54321 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        dns_pkt.time = t
        packets.append(dns_pkt)

        # HTTP/HTTPS requests
        http_pkt = IP(src=normal_client, dst=web_server) / TCP(sport=50000 + i, dport=443, flags="PA")
        http_pkt.time = t + 0.1
        packets.append(http_pkt)

        http_resp = IP(src=web_server, dst=normal_client) / TCP(sport=443, dport=50000 + i, flags="A")
        http_resp.time = t + 0.2
        packets.append(http_resp)

    # -------------------------------------------------------------
    # 2. Port Scanning Scenario
    # -------------------------------------------------------------
    # Attacker 192.168.1.105 probes 25 distinct ports on target 192.168.1.50 within 3.5 seconds
    scanner_ip = "192.168.1.105"
    scan_target = "192.168.1.50"
    scan_start = base_time + 25.0
    scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 9000
    ]

    for idx, port in enumerate(scan_ports):
        t = scan_start + (idx * 0.12)  # Probed within ~3 seconds
        scan_pkt = IP(src=scanner_ip, dst=scan_target) / TCP(sport=45000 + idx, dport=port, flags="S")
        scan_pkt.time = t
        packets.append(scan_pkt)

    # -------------------------------------------------------------
    # 3. Brute-Force Indicator Scenario (SSH Port 22)
    # -------------------------------------------------------------
    # Attacker 10.0.0.45 initiates 15 connection attempts to SSH (port 22) on 192.168.1.10 within 18 seconds
    bf_attacker = "10.0.0.45"
    ssh_target = "192.168.1.10"
    bf_start = base_time + 35.0

    for i in range(15):
        t = bf_start + (i * 1.1)  # ~16 seconds total
        bf_pkt = IP(src=bf_attacker, dst=ssh_target) / TCP(sport=38000 + i, dport=22, flags="S")
        bf_pkt.time = t
        packets.append(bf_pkt)

    # -------------------------------------------------------------
    # 4. Traffic Flooding Scenario (High Packet Rate Burst)
    # -------------------------------------------------------------
    # Attacker 172.16.0.99 sends 120 rapid UDP/TCP packets to 192.168.1.1 within 2.5 seconds
    flood_attacker = "172.16.0.99"
    flood_target = "192.168.1.1"
    flood_start = base_time + 60.0

    for i in range(120):
        t = flood_start + (i * 0.02)  # 120 packets in 2.4 seconds (> 45 packets/sec)
        flood_pkt = IP(src=flood_attacker, dst=flood_target) / UDP(sport=20000 + (i % 50), dport=80)
        flood_pkt.time = t
        packets.append(flood_pkt)

    # Ensure output directory exists
    parent = os.path.dirname(output_filepath)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

    # Write out PCAP
    wrpcap(output_filepath, packets)
    try:
        print(f"[SUCCESS] Synthetic test PCAP created with {len(packets)} packets at: {os.path.basename(output_filepath)}")
    except Exception:
        pass
    return True


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sample_file = os.path.join(current_dir, "sample_traffic.pcap")
    generate_synthetic_pcap(sample_file)
