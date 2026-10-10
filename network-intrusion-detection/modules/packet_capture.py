"""
Packet Capture and Parsing Module for Network Intrusion Detection System (NIDS).
Provides robust functions for offline PCAP/PCAPNG parsing, packet metadata extraction,
resilient error handling for malformed packets, and optional authorized live packet capture.
"""

import os
import io
import time
import tempfile
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple, Union

try:
    from scapy.all import (
        rdpcap,
        PcapReader,
        sniff,
        get_if_list,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        Packet
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Packet = Any

import pandas as pd


# Common TCP Flag bit mappings
TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def decode_tcp_flags(flags_val: Any) -> str:
    """
    Decodes Scapy TCP flag values or integers into a human-readable string (e.g., 'SYN, ACK').
    """
    if flags_val is None:
        return ""
    if isinstance(flags_val, str):
        return flags_val
    try:
        val = int(flags_val)
        active = [name for mask, name in TCP_FLAGS.items() if (val & mask) != 0]
        return ", ".join(active) if active else str(flags_val)
    except (ValueError, TypeError):
        return str(flags_val)


def parse_single_packet(packet: Any, packet_index: int = 0) -> Optional[Dict[str, Any]]:
    """
    Extracts structured security metadata from a single Scapy packet.
    Safely handles malformed packets, IPv6, ARP, ICMP, and missing fields.
    """
    try:
        # Extract packet timestamp
        raw_time = getattr(packet, "time", None)
        if raw_time is not None:
            try:
                epoch_time = float(raw_time)
                # Formatted ISO timestamp
                time_iso = datetime.fromtimestamp(epoch_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            except Exception:
                epoch_time = time.time()
                time_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        else:
            epoch_time = time.time()
            time_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        packet_size = len(packet) if hasattr(packet, "__len__") else 0

        # Layer 3: Network Layer (IP / IPv6 / ARP)
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol = "OTHER"

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src_ip = getattr(ip_layer, "src", "N/A")
            dst_ip = getattr(ip_layer, "dst", "N/A")
            proto_num = getattr(ip_layer, "proto", None)
            if proto_num == 6:
                protocol = "TCP"
            elif proto_num == 17:
                protocol = "UDP"
            elif proto_num == 1:
                protocol = "ICMP"
            else:
                protocol = f"IP-{proto_num}"
        elif packet.haslayer(IPv6):
            ipv6_layer = packet.getlayer(IPv6)
            src_ip = getattr(ipv6_layer, "src", "N/A")
            dst_ip = getattr(ipv6_layer, "dst", "N/A")
            nh = getattr(ipv6_layer, "nh", None)
            if nh == 6:
                protocol = "TCP"
            elif nh == 17:
                protocol = "UDP"
            elif nh == 58:
                protocol = "ICMPv6"
            else:
                protocol = "IPv6"
        elif packet.haslayer(ARP):
            arp_layer = packet.getlayer(ARP)
            src_ip = getattr(arp_layer, "psrc", "N/A")
            dst_ip = getattr(arp_layer, "pdst", "N/A")
            protocol = "ARP"

        # Layer 4: Transport Layer (TCP / UDP)
        src_port = None
        dst_port = None
        flags_str = ""
        is_syn = False

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            protocol = "TCP"
            src_port = getattr(tcp_layer, "sport", None)
            dst_port = getattr(tcp_layer, "dport", None)
            raw_flags = getattr(tcp_layer, "flags", "")
            flags_str = decode_tcp_flags(raw_flags)
            # Check for SYN flag alone (SYN scan / connection attempt indicator)
            if "SYN" in flags_str and "ACK" not in flags_str:
                is_syn = True
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            protocol = "UDP"
            src_port = getattr(udp_layer, "sport", None)
            dst_port = getattr(udp_layer, "dport", None)
            if packet.haslayer(DNS):
                protocol = "DNS"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        summary = ""
        try:
            summary = packet.summary()
        except Exception:
            summary = f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        return {
            "index": packet_index,
            "timestamp": epoch_time,
            "time_str": time_iso,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_size": packet_size,
            "tcp_flags": flags_str,
            "is_syn": is_syn,
            "summary": summary
        }
    except Exception as e:
        # Gracefully handle corrupted or truncated packet
        return {
            "index": packet_index,
            "timestamp": time.time(),
            "time_str": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "source_ip": "MALFORMED",
            "destination_ip": "MALFORMED",
            "source_port": None,
            "destination_port": None,
            "protocol": "MALFORMED",
            "packet_size": 0,
            "tcp_flags": "",
            "is_syn": False,
            "summary": f"Malformed packet parse error: {str(e)}"
        }


def read_pcap_file(
    source: Union[str, bytes, io.BytesIO],
    max_packets: Optional[int] = None
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Parses a PCAP or PCAPNG file from a file path, raw bytes, or BytesIO object.
    Returns: (list_of_parsed_packet_dicts, error_message_if_any)
    """
    if not SCAPY_AVAILABLE:
        return [], "Scapy library is not installed. Please run `pip install -r requirements.txt`."

    temp_path = None
    try:
        # Handle bytes or file-like buffer (e.g., Streamlit file uploader)
        if isinstance(source, bytes):
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(source)
                temp_path = tmp.name
            file_to_read = temp_path
        elif hasattr(source, "read"):
            # Streamlit UploadedFile or BytesIO
            content = source.read()
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                tmp.write(content)
                temp_path = tmp.name
            file_to_read = temp_path
        elif isinstance(source, str):
            if not os.path.exists(source):
                return [], f"PCAP file not found at path: {source}"
            file_to_read = source
        else:
            return [], "Unsupported source format. Expected file path, bytes, or file-like object."

        # Parse packets using Scapy PcapReader for memory efficiency
        parsed_packets: List[Dict[str, Any]] = []
        try:
            with PcapReader(file_to_read) as reader:
                idx = 0
                for pkt in reader:
                    parsed = parse_single_packet(pkt, packet_index=idx)
                    if parsed:
                        parsed_packets.append(parsed)
                    idx += 1
                    if max_packets and idx >= max_packets:
                        break
        except Exception as read_err:
            # Fallback to rdpcap if PcapReader encounters format variation
            try:
                packets = rdpcap(file_to_read)
                parsed_packets = []
                for idx, pkt in enumerate(packets):
                    parsed = parse_single_packet(pkt, packet_index=idx)
                    if parsed:
                        parsed_packets.append(parsed)
                    if max_packets and idx + 1 >= max_packets:
                        break
            except Exception as rdpcap_err:
                return [], f"Failed to parse PCAP file: {str(read_err)} / {str(rdpcap_err)}"

        return parsed_packets, None

    except Exception as e:
        return [], f"Unexpected error reading PCAP: {str(e)}"
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


def parse_packets_to_dataframe(parsed_packets: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Converts a list of parsed packet dictionaries into a sanitized Pandas DataFrame.
    """
    if not parsed_packets:
        return pd.DataFrame(columns=[
            "index", "timestamp", "time_str", "source_ip", "destination_ip",
            "source_port", "destination_port", "protocol", "packet_size",
            "tcp_flags", "is_syn", "summary"
        ])
    df = pd.DataFrame(parsed_packets)
    # Ensure standard types
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    if "packet_size" in df.columns:
        df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce").fillna(0).astype(int)
    return df


def check_live_capture_status() -> Tuple[bool, str]:
    """
    Verifies if live network packet capture is supported on the current operating system.
    Returns: (is_supported: bool, message: str)
    """
    if not SCAPY_AVAILABLE:
        return False, "Scapy is not installed. Live capture unavailable."

    import platform
    current_os = platform.system()

    try:
        if current_os == "Windows":
            # On Windows, Scapy requires Npcap (or WinPcap) with administrator rights
            interfaces = get_if_list()
            if not interfaces:
                return False, (
                    "No capture interfaces detected. Windows requires Npcap (https://npcap.com/) "
                    "installed in WinPcap API-compatible mode with administrative privileges."
                )
            return True, f"Windows capture ready. {len(interfaces)} interface(s) detected. Ensure Streamlit has admin/Npcap rights."
        else:
            # Linux / macOS check
            if os.geteuid() != 0:
                return False, "Linux/macOS live capture requires root privileges (e.g., `sudo streamlit run app.py` or `setcap cap_net_raw,cap_net_admin=eip`)."
            return True, "Live capture permitted on Linux/macOS with root privileges."
    except Exception as e:
        return False, f"Capture capability check warning: {str(e)}"


def get_available_interfaces() -> List[str]:
    """
    Returns a safe list of available network interfaces for live capture.
    """
    if not SCAPY_AVAILABLE:
        return []
    try:
        interfaces = get_if_list()
        return interfaces if interfaces else ["Default"]
    except Exception:
        return ["Default"]


def capture_live_packets(
    interface: Optional[str] = None,
    packet_count: int = 50,
    timeout: int = 5
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Captures live packets from an authorized network interface using Scapy.
    Returns: (parsed_packets, error_message)
    """
    if not SCAPY_AVAILABLE:
        return [], "Scapy is not installed."

    try:
        kwargs: Dict[str, Any] = {
            "count": packet_count,
            "timeout": timeout,
            "store": True
        }
        if interface and interface != "Default":
            kwargs["iface"] = interface

        scapy_packets = sniff(**kwargs)
        parsed = [parse_single_packet(p, idx) for idx, p in enumerate(scapy_packets)]
        parsed_clean = [p for p in parsed if p is not None]
        return parsed_clean, None
    except PermissionError:
        return [], "Permission denied: Live network packet capture requires elevated administrator/root permissions."
    except Exception as e:
        return [], f"Live capture encountered an error: {str(e)}"
