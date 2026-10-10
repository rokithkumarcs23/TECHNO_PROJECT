"""
Unit Tests for Database Persistence Module in Network Intrusion Detection System (NIDS).
Tests SQLite schema initialization, alert insertion, parameterized filtering,
metrics computation, and CSV export.
"""

import os
import tempfile
import pytest
from modules.database import (
    init_db,
    insert_alert,
    insert_alerts_batch,
    get_alerts,
    get_alerts_dataframe,
    get_alert_counts,
    export_alerts_to_csv,
    clear_all_alerts
)


@pytest.fixture
def temp_db():
    """
    Creates a temporary SQLite database file for isolated testing and cleans it up after test execution.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass


def test_db_initialization_and_single_insert(temp_db):
    """
    Verifies that the alerts table is initialized and single alert insertion succeeds.
    """
    test_alert = {
        "id": "alert-test-001",
        "timestamp": "2026-10-10 12:00:00.000",
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.1",
        "attack_type": "Port Scanning",
        "severity": "High",
        "description": "Port scan observed against gateway",
        "evidence": '{"distinct_ports": 25}'
    }

    success = insert_alert(test_alert, db_path=temp_db)
    assert success is True

    alerts = get_alerts(db_path=temp_db)
    assert len(alerts) == 1
    assert alerts[0]["id"] == "alert-test-001"
    assert alerts[0]["attack_type"] == "Port Scanning"
    assert alerts[0]["severity"] == "High"


def test_batch_insertion_and_filtering(temp_db):
    """
    Verifies batch insertion and parameterized query filters for attack type, severity, and source IP.
    """
    alerts = [
        {
            "id": "a-1",
            "timestamp": "2026-10-10 12:01:00.000",
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.1",
            "attack_type": "Port Scanning",
            "severity": "Medium",
            "description": "Port scan 1",
            "evidence": "{}"
        },
        {
            "id": "a-2",
            "timestamp": "2026-10-10 12:02:00.000",
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.10",
            "attack_type": "Suspected Brute-Force Attempt",
            "severity": "High",
            "description": "SSH Brute Force",
            "evidence": "{}"
        },
        {
            "id": "a-3",
            "timestamp": "2026-10-10 12:03:00.000",
            "source_ip": "172.16.0.2",
            "destination_ip": "192.168.1.20",
            "attack_type": "Suspected Traffic Flooding",
            "severity": "High",
            "description": "UDP Flood",
            "evidence": "{}"
        }
    ]

    inserted = insert_alerts_batch(alerts, db_path=temp_db)
    assert inserted >= 3

    # Filter by attack type
    port_scans = get_alerts(attack_type="Port Scanning", db_path=temp_db)
    assert len(port_scans) == 1
    assert port_scans[0]["id"] == "a-1"

    # Filter by severity
    high_sevs = get_alerts(severity="High", db_path=temp_db)
    assert len(high_sevs) == 2

    # Filter by source IP
    source_results = get_alerts(source_ip="10.0.0.5", db_path=temp_db)
    assert len(source_results) == 2


def test_alert_counts_aggregation(temp_db):
    """
    Verifies that the alert counter summary matches stored records.
    """
    alerts = [
        {"id": "c-1", "timestamp": "2026-10-10 10:00:00", "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "attack_type": "Port Scanning", "severity": "High", "description": "", "evidence": ""},
        {"id": "c-2", "timestamp": "2026-10-10 10:01:00", "source_ip": "1.1.1.2", "destination_ip": "2.2.2.2", "attack_type": "Suspected Brute-Force Attempt", "severity": "Medium", "description": "", "evidence": ""},
        {"id": "c-3", "timestamp": "2026-10-10 10:02:00", "source_ip": "1.1.1.3", "destination_ip": "2.2.2.2", "attack_type": "Suspected Traffic Flooding", "severity": "High", "description": "", "evidence": ""},
    ]
    insert_alerts_batch(alerts, db_path=temp_db)

    counts = get_alert_counts(db_path=temp_db)
    assert counts["total"] == 3
    assert counts["port_scan"] == 1
    assert counts["brute_force"] == 1
    assert counts["flooding"] == 1
    assert counts["high_severity"] == 2
    assert counts["medium_severity"] == 1


def test_csv_export_and_clear(temp_db):
    """
    Verifies CSV export and database truncation.
    """
    test_alert = {
        "id": "exp-01",
        "timestamp": "2026-10-10 10:30:00",
        "source_ip": "192.168.1.99",
        "destination_ip": "192.168.1.1",
        "attack_type": "Port Scanning",
        "severity": "Low",
        "description": "Test scan",
        "evidence": "{}"
    }
    insert_alert(test_alert, db_path=temp_db)

    # Export to CSV
    export_file = temp_db.replace(".db", ".csv")
    out_path = export_alerts_to_csv(filepath=export_file, db_path=temp_db)
    assert os.path.exists(out_path)
    with open(out_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "exp-01" in content
        assert "192.168.1.99" in content

    # Clean up exported CSV
    if os.path.exists(out_path):
        os.remove(out_path)

    # Clear database
    cleared = clear_all_alerts(db_path=temp_db)
    assert cleared is True
    assert len(get_alerts(db_path=temp_db)) == 0
