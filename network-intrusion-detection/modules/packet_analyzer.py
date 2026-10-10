"""
Packet Analyzer Module for Network Intrusion Detection System (NIDS).
Performs statistical aggregation, protocol breakdown, time-series traffic summarization,
and port/service mapping using Pandas for high-performance dashboard charts.
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np


# Well-known service port definitions for human-readable dashboard displays
KNOWN_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt"
}


def compute_traffic_metrics(df_packets: pd.DataFrame) -> Dict[str, Any]:
    """
    Computes summary metrics for analyzed traffic: total packets, byte volume,
    duration, average size, and transmission rate.
    """
    if df_packets is None or df_packets.empty:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "duration_seconds": 0.0,
            "avg_packet_size": 0.0,
            "packet_rate": 0.0,
            "bandwidth_kbps": 0.0,
            "unique_sources": 0,
            "unique_destinations": 0
        }

    total_packets = len(df_packets)
    total_bytes = int(df_packets["packet_size"].sum()) if "packet_size" in df_packets.columns else 0
    avg_size = float(df_packets["packet_size"].mean()) if total_packets > 0 else 0.0

    duration = 0.0
    if "timestamp" in df_packets.columns:
        valid_ts = df_packets["timestamp"].dropna()
        if len(valid_ts) >= 2:
            duration = float(valid_ts.max() - valid_ts.min())
            if duration <= 0:
                duration = 1.0
        else:
            duration = 1.0

    packet_rate = (total_packets / duration) if duration > 0 else 0.0
    bandwidth_kbps = ((total_bytes * 8) / (duration * 1000)) if duration > 0 else 0.0

    unique_sources = df_packets["source_ip"].nunique() if "source_ip" in df_packets.columns else 0
    unique_dests = df_packets["destination_ip"].nunique() if "destination_ip" in df_packets.columns else 0

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": round(duration, 2),
        "avg_packet_size": round(avg_size, 1),
        "packet_rate": round(packet_rate, 2),
        "bandwidth_kbps": round(bandwidth_kbps, 2),
        "unique_sources": unique_sources,
        "unique_destinations": unique_dests
    }


def get_protocol_distribution(df_packets: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregates packet counts and percentage by network protocol.
    """
    if df_packets is None or df_packets.empty or "protocol" not in df_packets.columns:
        return pd.DataFrame(columns=["protocol", "count", "percentage"])

    counts = df_packets["protocol"].value_counts().reset_index()
    counts.columns = ["protocol", "count"]
    total = counts["count"].sum()
    counts["percentage"] = ((counts["count"] / total) * 100).round(1)
    return counts


def get_packets_over_time(df_packets: pd.DataFrame, bins: int = 30) -> pd.DataFrame:
    """
    Aggregates packet volume into discrete temporal bins for time-series charts.
    """
    if df_packets is None or df_packets.empty or "timestamp" not in df_packets.columns:
        return pd.DataFrame(columns=["time_bucket", "packet_count", "byte_count"])

    clean_df = df_packets.dropna(subset=["timestamp"]).copy()
    if clean_df.empty:
        return pd.DataFrame(columns=["time_bucket", "packet_count", "byte_count"])

    clean_df["timestamp"] = pd.to_numeric(clean_df["timestamp"], errors="coerce")
    clean_df = clean_df.sort_values("timestamp")

    min_ts = clean_df["timestamp"].min()
    max_ts = clean_df["timestamp"].max()

    if max_ts == min_ts:
        clean_df["datetime"] = pd.to_datetime(clean_df["timestamp"], unit="s")
        return pd.DataFrame([{
            "time_bucket": clean_df["datetime"].iloc[0].strftime("%H:%M:%S"),
            "packet_count": len(clean_df),
            "byte_count": clean_df["packet_size"].sum() if "packet_size" in clean_df.columns else 0
        }])

    clean_df["datetime"] = pd.to_datetime(clean_df["timestamp"], unit="s")
    # Resample or cut into bins
    clean_df["bin"] = pd.cut(clean_df["timestamp"], bins=bins)
    grouped = clean_df.groupby("bin", observed=False).agg(
        packet_count=("timestamp", "count"),
        byte_count=("packet_size", "sum"),
        mid_time=("timestamp", "mean")
    ).reset_index()

    grouped = grouped[grouped["packet_count"] > 0]
    grouped["time_bucket"] = pd.to_datetime(grouped["mid_time"], unit="s").dt.strftime("%H:%M:%S")

    return grouped[["time_bucket", "packet_count", "byte_count"]]


def get_top_sources(df_packets: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """
    Returns top source IP addresses by packet count.
    """
    if df_packets is None or df_packets.empty or "source_ip" not in df_packets.columns:
        return pd.DataFrame(columns=["source_ip", "packet_count"])

    filtered = df_packets[~df_packets["source_ip"].isin(["N/A", "MALFORMED", ""])]
    counts = filtered["source_ip"].value_counts().head(top_n).reset_index()
    counts.columns = ["source_ip", "packet_count"]
    return counts


def get_top_destinations(df_packets: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """
    Returns top destination IP addresses by packet count.
    """
    if df_packets is None or df_packets.empty or "destination_ip" not in df_packets.columns:
        return pd.DataFrame(columns=["destination_ip", "packet_count"])

    filtered = df_packets[~df_packets["destination_ip"].isin(["N/A", "MALFORMED", ""])]
    counts = filtered["destination_ip"].value_counts().head(top_n).reset_index()
    counts.columns = ["destination_ip", "packet_count"]
    return counts


def get_destination_ports_summary(df_packets: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """
    Returns top destination ports, resolving them to known service names.
    """
    if df_packets is None or df_packets.empty or "destination_port" not in df_packets.columns:
        return pd.DataFrame(columns=["port_label", "packet_count"])

    valid_ports = df_packets.dropna(subset=["destination_port"]).copy()
    valid_ports = valid_ports[valid_ports["destination_port"] > 0]

    if valid_ports.empty:
        return pd.DataFrame(columns=["port_label", "packet_count"])

    counts = valid_ports["destination_port"].value_counts().head(top_n).reset_index()
    counts.columns = ["port", "packet_count"]

    def format_port_label(p: int) -> str:
        p_int = int(p)
        service = KNOWN_SERVICES.get(p_int, "Other")
        return f"{p_int} ({service})"

    counts["port_label"] = counts["port"].apply(format_port_label)
    return counts[["port_label", "packet_count"]]
