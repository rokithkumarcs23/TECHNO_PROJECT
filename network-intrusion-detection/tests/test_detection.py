"""
Unit Tests for Detection Engine in Network Intrusion Detection System (NIDS).
Tests port scan detection, brute-force indicators, traffic flooding,
normal traffic baselines, duplicate suppression, and timestamp ordering.
"""

import pytest
import time
import json
from modules.detection_engine import DetectionEngine


def test_normal_traffic_baseline():
    """
    Verifies that benign web and DNS traffic below all thresholds generates zero false alerts.
    """
    engine = DetectionEngine(
        port_scan_threshold=20,
        port_scan_window=10.0,
        brute_force_threshold=10,
        brute_force_window=60.0,
        flooding_threshold=100,
        flooding_window=5.0
    )

    base_time = 1000.0
    normal_packets = []
    # 5 standard HTTPS requests spread over 10 seconds
    for i in range(5):
        normal_packets.append({
            "timestamp": base_time + (i * 2.0),
            "source_ip": "192.168.1.50",
            "destination_ip": "142.250.190.46",
            "source_port": 50000 + i,
            "destination_port": 443,
            "protocol": "TCP",
            "is_syn": False,
            "packet_size": 250
        })

    alerts = engine.process_packet_stream(normal_packets)
    assert len(alerts) == 0, f"Expected 0 alerts for normal traffic, got {len(alerts)}"


def test_port_scan_detection_triggered():
    """
    Verifies that scanning distinct destination ports exceeding the threshold triggers a Port Scanning alert.
    """
    engine = DetectionEngine(
        port_scan_threshold=15,
        port_scan_window=10.0,
        cooldown_seconds=30.0
    )

    base_time = 2000.0
    scan_packets = []
    # 20 distinct destination ports in 2 seconds
    for p in range(20):
        scan_packets.append({
            "timestamp": base_time + (p * 0.1),
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "source_port": 40000 + p,
            "destination_port": 80 + p,  # 80, 81, 82 ... distinct
            "protocol": "TCP",
            "is_syn": True,
            "packet_size": 60
        })

    alerts = engine.process_packet_stream(scan_packets)
    assert len(alerts) >= 1
    scan_alert = alerts[0]
    assert scan_alert["attack_type"] == "Port Scanning"
    assert scan_alert["source_ip"] == "10.0.0.99"
    assert scan_alert["severity"] in ["Medium", "High"]

    evidence = json.loads(scan_alert["evidence"])
    assert evidence["distinct_ports_count"] >= 15


def test_port_scan_below_threshold_ignored():
    """
    Verifies that scanning fewer ports than the threshold does not trigger an alert.
    """
    engine = DetectionEngine(
        port_scan_threshold=20,
        port_scan_window=10.0
    )

    base_time = 3000.0
    scan_packets = []
    # Only 8 distinct ports probed
    for p in range(8):
        scan_packets.append({
            "timestamp": base_time + (p * 0.2),
            "source_ip": "10.0.0.99",
            "destination_ip": "192.168.1.1",
            "source_port": 40000 + p,
            "destination_port": 1000 + p,
            "protocol": "TCP",
            "is_syn": True,
            "packet_size": 60
        })

    alerts = engine.process_packet_stream(scan_packets)
    assert len(alerts) == 0


def test_brute_force_indicator_triggered():
    """
    Verifies repeated connection attempts against a single service exceeding threshold triggers alert.
    """
    engine = DetectionEngine(
        brute_force_threshold=10,
        brute_force_window=30.0,
        cooldown_seconds=60.0
    )

    base_time = 4000.0
    bf_packets = []
    # 12 connection attempts to SSH port 22 in 10 seconds
    for i in range(12):
        bf_packets.append({
            "timestamp": base_time + (i * 0.8),
            "source_ip": "192.168.1.200",
            "destination_ip": "192.168.1.10",
            "source_port": 51000 + i,
            "destination_port": 22,
            "protocol": "TCP",
            "is_syn": True,
            "packet_size": 64
        })

    alerts = engine.process_packet_stream(bf_packets)
    assert len(alerts) >= 1
    bf_alert = alerts[0]
    assert bf_alert["attack_type"] == "Suspected Brute-Force Attempt"
    assert bf_alert["source_ip"] == "192.168.1.200"

    evidence = json.loads(bf_alert["evidence"])
    assert evidence["attempts_count"] >= 10
    assert evidence["target_port"] == 22


def test_traffic_flooding_detection_triggered():
    """
    Verifies that excessive packet volume from a source exceeding the rate threshold triggers Flooding alert.
    """
    engine = DetectionEngine(
        flooding_threshold=50,
        flooding_window=2.0,
        cooldown_seconds=30.0
    )

    base_time = 5000.0
    flood_packets = []
    # 60 packets sent in 1.2 seconds
    for i in range(60):
        flood_packets.append({
            "timestamp": base_time + (i * 0.02),
            "source_ip": "172.16.5.5",
            "destination_ip": "192.168.1.254",
            "source_port": 30000,
            "destination_port": 80,
            "protocol": "UDP",
            "is_syn": False,
            "packet_size": 512
        })

    alerts = engine.process_packet_stream(flood_packets)
    assert len(alerts) >= 1
    flood_alert = alerts[0]
    assert flood_alert["attack_type"] == "Suspected Traffic Flooding"
    assert flood_alert["source_ip"] == "172.16.5.5"

    evidence = json.loads(flood_alert["evidence"])
    assert evidence["observed_packets"] >= 50


def test_duplicate_alert_suppression():
    """
    Verifies that continuous bursts during the cooldown period do not flood the system with redundant alerts.
    """
    engine = DetectionEngine(
        flooding_threshold=20,
        flooding_window=2.0,
        cooldown_seconds=15.0
    )

    base_time = 6000.0
    burst_packets = []
    # Send 100 packets in 4 seconds (all within the 15-second cooldown window)
    for i in range(100):
        burst_packets.append({
            "timestamp": base_time + (i * 0.04),
            "source_ip": "10.10.10.10",
            "destination_ip": "10.10.10.1",
            "source_port": 12345,
            "destination_port": 9999,
            "protocol": "UDP",
            "is_syn": False,
            "packet_size": 100
        })

    alerts = engine.process_packet_stream(burst_packets)
    # Even though 100 packets arrived and threshold is 20, exactly 1 alert should be generated due to cooldown
    assert len(alerts) == 1, f"Expected 1 suppressed alert, got {len(alerts)}"


def test_out_of_order_timestamp_handling():
    """
    Verifies that packets arriving with out-of-order timestamps are sorted properly and detected accurately.
    """
    engine = DetectionEngine(
        port_scan_threshold=10,
        port_scan_window=5.0,
        cooldown_seconds=20.0
    )

    base_time = 7000.0
    # Create packets with ordered timestamps
    packets = [
        {
            "timestamp": base_time + (i * 0.2),
            "source_ip": "192.168.1.77",
            "destination_ip": "192.168.1.1",
            "source_port": 50000,
            "destination_port": 2000 + i,
            "protocol": "TCP",
            "is_syn": True,
            "packet_size": 60
        }
        for i in range(12)
    ]

    # Deliberately reverse the packet list to simulate out-of-order capture
    reversed_packets = list(reversed(packets))

    # process_packet_stream sorts them by timestamp
    alerts = engine.process_packet_stream(reversed_packets)
    assert len(alerts) >= 1
    assert alerts[0]["attack_type"] == "Port Scanning"
