"""
Detection Engine Module for Network Intrusion Detection System (NIDS).
Implements stateful, rule-based threat detection using rolling time windows,
duplicate suppression via cooldowns, attack classification, and evidence synthesis.

Supported Threat Categories:
1. Port Scanning: High volume of distinct destination ports from a single source within a time window.
2. Suspected Brute-Force: Repeated TCP connection attempts against a specific destination service.
3. Suspected Traffic Flooding: Abnormally high packet frequency from a source within a time window.
"""

import uuid
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple
import pandas as pd


# Default Rule Thresholds
DEFAULT_PORT_SCAN_THRESHOLD = 20        # Distinct ports
DEFAULT_PORT_SCAN_WINDOW = 10.0         # Seconds
DEFAULT_BRUTE_FORCE_THRESHOLD = 10      # Connection attempts to a service
DEFAULT_BRUTE_FORCE_WINDOW = 60.0       # Seconds
DEFAULT_FLOODING_THRESHOLD = 100        # Packets per source
DEFAULT_FLOODING_WINDOW = 5.0           # Seconds
DEFAULT_ALERT_COOLDOWN = 20.0           # Seconds before repeating same alert type per source

# High-value authentication/service ports monitored for brute-force indicators
AUTHENTICATION_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt"
}


class DetectionEngine:
    """
    Stateful rule-based Network Intrusion Detection Engine.
    Uses sliding timestamp-based deques for efficient O(1) rolling window checks.
    """

    def __init__(
        self,
        port_scan_threshold: int = DEFAULT_PORT_SCAN_THRESHOLD,
        port_scan_window: float = DEFAULT_PORT_SCAN_WINDOW,
        brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
        brute_force_window: float = DEFAULT_BRUTE_FORCE_WINDOW,
        flooding_threshold: int = DEFAULT_FLOODING_THRESHOLD,
        flooding_window: float = DEFAULT_FLOODING_WINDOW,
        cooldown_seconds: float = DEFAULT_ALERT_COOLDOWN
    ):
        self.port_scan_threshold = int(port_scan_threshold)
        self.port_scan_window = float(port_scan_window)
        self.brute_force_threshold = int(brute_force_threshold)
        self.brute_force_window = float(brute_force_window)
        self.flooding_threshold = int(flooding_threshold)
        self.flooding_window = float(flooding_window)
        self.cooldown_seconds = float(cooldown_seconds)

        # State storage for rolling windows:
        # source_ip -> deque of (timestamp, dst_port, dst_ip)
        self._port_scan_windows: Dict[str, deque] = defaultdict(deque)

        # (source_ip, dst_ip, dst_port) -> deque of timestamp
        self._service_conn_windows: Dict[Tuple[str, str, int], deque] = defaultdict(deque)

        # source_ip -> deque of timestamp
        self._flood_windows: Dict[str, deque] = defaultdict(deque)

        # Alert cooldown tracker: (source_ip, attack_type, target_key) -> last_alert_timestamp
        self._alert_cooldowns: Dict[Tuple[str, str, str], float] = {}

    def update_config(
        self,
        port_scan_threshold: Optional[int] = None,
        port_scan_window: Optional[float] = None,
        brute_force_threshold: Optional[int] = None,
        brute_force_window: Optional[float] = None,
        flooding_threshold: Optional[int] = None,
        flooding_window: Optional[float] = None,
        cooldown_seconds: Optional[float] = None
    ) -> None:
        """
        Dynamically updates detection thresholds from dashboard inputs.
        """
        if port_scan_threshold is not None:
            self.port_scan_threshold = int(port_scan_threshold)
        if port_scan_window is not None:
            self.port_scan_window = float(port_scan_window)
        if brute_force_threshold is not None:
            self.brute_force_threshold = int(brute_force_threshold)
        if brute_force_window is not None:
            self.brute_force_window = float(brute_force_window)
        if flooding_threshold is not None:
            self.flooding_threshold = int(flooding_threshold)
        if flooding_window is not None:
            self.flooding_window = float(flooding_window)
        if cooldown_seconds is not None:
            self.cooldown_seconds = float(cooldown_seconds)

    def reset_state(self) -> None:
        """
        Clears all in-memory rolling tracking buffers and cooldown timers.
        """
        self._port_scan_windows.clear()
        self._service_conn_windows.clear()
        self._flood_windows.clear()
        self._alert_cooldowns.clear()

    def _is_cooling_down(self, source_ip: str, attack_type: str, target_key: str, current_ts: float) -> bool:
        """
        Checks whether an alert of the same category and target is within its cooldown period.
        """
        key = (source_ip, attack_type, target_key)
        last_time = self._alert_cooldowns.get(key)
        if last_time is not None:
            if current_ts - last_time < self.cooldown_seconds:
                return True
        self._alert_cooldowns[key] = current_ts
        return False

    def process_packet(self, packet_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Ingests a single parsed packet dictionary and evaluates all rule engines.
        Returns a list of generated alert dictionaries, or an empty list if normal traffic.
        """
        alerts: List[Dict[str, Any]] = []

        src_ip = packet_dict.get("source_ip", "")
        dst_ip = packet_dict.get("destination_ip", "")
        dst_port = packet_dict.get("destination_port")
        proto = packet_dict.get("protocol", "")
        ts = float(packet_dict.get("timestamp", 0.0))
        is_syn = packet_dict.get("is_syn", False)

        # Ignore non-routable / malformed / broadcast baseline packets
        if not src_ip or src_ip in ["N/A", "MALFORMED", "255.255.255.255"]:
            return alerts

        # -------------------------------------------------------------
        # 1. Traffic Flooding Detection
        # -------------------------------------------------------------
        flood_q = self._flood_windows[src_ip]
        flood_q.append(ts)
        cutoff_flood = ts - self.flooding_window
        while flood_q and flood_q[0] < cutoff_flood:
            flood_q.popleft()

        packet_count = len(flood_q)
        if packet_count >= self.flooding_threshold:
            target_key = dst_ip if dst_ip else "global"
            if not self._is_cooling_down(src_ip, "Suspected Traffic Flooding", target_key, ts):
                rate = packet_count / (self.flooding_window if self.flooding_window > 0 else 1.0)
                severity = "High" if packet_count >= (self.flooding_threshold * 2) else "Medium"

                evidence = {
                    "rule": "Traffic Flooding Threshold",
                    "observed_packets": packet_count,
                    "threshold": self.flooding_threshold,
                    "window_seconds": self.flooding_window,
                    "rate_packets_per_sec": round(rate, 1),
                    "primary_target": dst_ip
                }

                alert = {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "source_ip": src_ip,
                    "destination_ip": dst_ip if dst_ip else "Multiple/Broadcast",
                    "attack_type": "Suspected Traffic Flooding",
                    "severity": severity,
                    "description": (
                        f"Excessive packet rate detected: {packet_count} packets from {src_ip} "
                        f"in {self.flooding_window:.1f}s (Threshold: {self.flooding_threshold})."
                    ),
                    "evidence": json.dumps(evidence)
                }
                alerts.append(alert)

        # -------------------------------------------------------------
        # 2. Port Scan Detection
        # -------------------------------------------------------------
        if dst_port is not None and dst_port > 0:
            scan_q = self._port_scan_windows[src_ip]
            scan_q.append((ts, int(dst_port), dst_ip))
            cutoff_scan = ts - self.port_scan_window
            while scan_q and scan_q[0][0] < cutoff_scan:
                scan_q.popleft()

            # Measure distinct destination ports targeted within window
            distinct_ports: Set[int] = {entry[1] for entry in scan_q}
            if len(distinct_ports) >= self.port_scan_threshold:
                target_key = dst_ip if dst_ip else "network"
                if not self._is_cooling_down(src_ip, "Port Scanning", target_key, ts):
                    severity = "High" if len(distinct_ports) >= (self.port_scan_threshold * 2) else "Medium"
                    sorted_ports = sorted(list(distinct_ports))
                    sample_ports = sorted_ports[:15]

                    evidence = {
                        "rule": "Distinct Destination Ports Window",
                        "distinct_ports_count": len(distinct_ports),
                        "threshold": self.port_scan_threshold,
                        "window_seconds": self.port_scan_window,
                        "sample_ports_targeted": sample_ports,
                        "primary_target_ip": dst_ip
                    }

                    alert = {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "source_ip": src_ip,
                        "destination_ip": dst_ip if dst_ip else "Subnet",
                        "attack_type": "Port Scanning",
                        "severity": severity,
                        "description": (
                            f"Port scan activity detected from {src_ip}: {len(distinct_ports)} distinct ports "
                            f"probed in {self.port_scan_window:.1f}s (Threshold: {self.port_scan_threshold})."
                        ),
                        "evidence": json.dumps(evidence)
                    }
                    alerts.append(alert)

        # -------------------------------------------------------------
        # 3. Brute-Force Indicator Detection (TCP Repeated Connections)
        # -------------------------------------------------------------
        # Focus on repeated connection attempts / SYN packets to specific service ports
        if dst_port is not None and (is_syn or (proto == "TCP" and int(dst_port) in AUTHENTICATION_SERVICES)):
            conn_key = (src_ip, dst_ip, int(dst_port))
            service_q = self._service_conn_windows[conn_key]
            service_q.append(ts)
            cutoff_bf = ts - self.brute_force_window
            while service_q and service_q[0] < cutoff_bf:
                service_q.popleft()

            attempt_count = len(service_q)
            if attempt_count >= self.brute_force_threshold:
                target_key = f"{dst_ip}:{dst_port}"
                if not self._is_cooling_down(src_ip, "Suspected Brute-Force Attempt", target_key, ts):
                    svc_name = AUTHENTICATION_SERVICES.get(int(dst_port), f"Port {dst_port}")
                    # Higher severity if targeting well-known sensitive authentication services
                    is_critical_service = dst_port in [22, 3389, 445, 1433, 3306]
                    severity = "High" if (is_critical_service or attempt_count >= (self.brute_force_threshold * 2)) else "Medium"

                    evidence = {
                        "rule": "Repeated Service Connection Attempts",
                        "attempts_count": attempt_count,
                        "threshold": self.brute_force_threshold,
                        "window_seconds": self.brute_force_window,
                        "target_ip": dst_ip,
                        "target_port": int(dst_port),
                        "target_service": svc_name,
                        "metadata_note": (
                            "Indicator based on network TCP connection frequency. "
                            "Actual credential authentication results require application auth log inspection."
                        )
                    }

                    alert = {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "attack_type": "Suspected Brute-Force Attempt",
                        "severity": severity,
                        "description": (
                            f"Repeated connection attempts ({attempt_count}) from {src_ip} "
                            f"to {dst_ip}:{dst_port} ({svc_name}) in {self.brute_force_window:.1f}s."
                        ),
                        "evidence": json.dumps(evidence)
                    }
                    alerts.append(alert)

        return alerts

    def process_packet_stream(self, packet_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes an entire stream or list of packets.
        Sorts records by timestamp to handle out-of-order offline captures cleanly.
        """
        if not packet_records:
            return []

        # Sort packets by timestamp to guarantee proper rolling window progression
        try:
            sorted_packets = sorted(
                packet_records,
                key=lambda p: float(p.get("timestamp", 0.0))
            )
        except Exception:
            sorted_packets = packet_records

        all_alerts: List[Dict[str, Any]] = []
        for pkt in sorted_packets:
            alerts = self.process_packet(pkt)
            if alerts:
                all_alerts.extend(alerts)

        return all_alerts

    def process_dataframe(self, df_packets: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Analyzes a Pandas DataFrame of packet records.
        """
        if df_packets is None or df_packets.empty:
            return []

        records = df_packets.to_dict(orient="records")
        return self.process_packet_stream(records)
