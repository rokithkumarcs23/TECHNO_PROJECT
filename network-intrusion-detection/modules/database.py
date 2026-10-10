"""
Database Persistence Module for Network Intrusion Detection System (NIDS).
Handles automatic SQLite database initialization, thread-safe connection management,
parameterized SQL queries, event filtering, batch insertions, and CSV export.
"""

import os
import sqlite3
import pandas as pd
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

# Default database path relative to project structure
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "nids_events.db"
)


def get_db_path(custom_path: Optional[str] = None) -> str:
    """
    Returns the resolved database path, ensuring the parent directory exists.
    """
    path = custom_path if custom_path else DEFAULT_DB_PATH
    parent_dir = os.path.dirname(path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)
    return path


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Establishes and returns a thread-safe SQLite connection with row factories enabled.
    """
    resolved_path = get_db_path(db_path)
    conn = sqlite3.connect(resolved_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initializes the SQLite database and creates the alerts table and indices if they do not exist.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT
            );
        """)
        # Create indices for high-frequency filtering and dashboard queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts (attack_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);")
        conn.commit()


def insert_alert(alert: Dict[str, Any], db_path: Optional[str] = None) -> bool:
    """
    Inserts a single security alert into the database using parameterized SQL.
    Returns True on success, False otherwise.
    """
    init_db(db_path)
    query = """
        INSERT OR IGNORE INTO alerts (
            id, timestamp, source_ip, destination_ip, attack_type, severity, description, evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """
    try:
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                str(alert.get("id", "")),
                str(alert.get("timestamp", datetime.now(timezone.utc).isoformat())),
                str(alert.get("source_ip", "Unknown")),
                str(alert.get("destination_ip", "N/A")),
                str(alert.get("attack_type", "Unknown")),
                str(alert.get("severity", "Low")),
                str(alert.get("description", "")),
                str(alert.get("evidence", ""))
            ))
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        print(f"[ERROR] Database insertion failed: {e}")
        return False


def insert_alerts_batch(alerts: List[Dict[str, Any]], db_path: Optional[str] = None) -> int:
    """
    Inserts multiple security alerts inside a single transaction.
    Returns the count of successfully inserted records.
    """
    if not alerts:
        return 0

    init_db(db_path)
    query = """
        INSERT OR IGNORE INTO alerts (
            id, timestamp, source_ip, destination_ip, attack_type, severity, description, evidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """
    inserted_count = 0
    try:
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            records = [
                (
                    str(a.get("id", "")),
                    str(a.get("timestamp", datetime.now(timezone.utc).isoformat())),
                    str(a.get("source_ip", "Unknown")),
                    str(a.get("destination_ip", "N/A")),
                    str(a.get("attack_type", "Unknown")),
                    str(a.get("severity", "Low")),
                    str(a.get("description", "")),
                    str(a.get("evidence", ""))
                )
                for a in alerts
            ]
            cursor.executemany(query, records)
            conn.commit()
            inserted_count = cursor.rowcount
    except Exception as e:
        print(f"[ERROR] Batch insertion failed: {e}")
    return inserted_count


def get_alerts(
    limit: int = 500,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves filtered security alerts ordered by timestamp descending.
    All filters utilize parameterized queries.
    """
    init_db(db_path)
    conditions = []
    params: List[Any] = []

    if attack_type and attack_type != "All":
        conditions.append("attack_type = ?")
        params.append(attack_type)

    if severity and severity != "All":
        conditions.append("severity = ?")
        params.append(severity)

    if source_ip and source_ip.strip():
        conditions.append("source_ip LIKE ?")
        params.append(f"%{source_ip.strip()}%")

    if start_time:
        conditions.append("timestamp >= ?")
        params.append(start_time)

    if end_time:
        conditions.append("timestamp <= ?")
        params.append(end_time)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT id, timestamp, source_ip, destination_ip, attack_type, severity, description, evidence
        FROM alerts
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ?;
    """
    params.append(limit)

    results: List[Dict[str, Any]] = []
    try:
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            for row in cursor.fetchall():
                results.append(dict(row))
    except Exception as e:
        print(f"[ERROR] Fetching alerts failed: {e}")

    return results


def get_alerts_dataframe(
    limit: int = 1000,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    db_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Retrieves alerts as a Pandas DataFrame for dashboard rendering and statistical analysis.
    """
    alerts = get_alerts(
        limit=limit,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        db_path=db_path
    )
    if not alerts:
        return pd.DataFrame(columns=[
            "id", "timestamp", "source_ip", "destination_ip",
            "attack_type", "severity", "description", "evidence"
        ])
    return pd.DataFrame(alerts)


def get_alert_counts(db_path: Optional[str] = None) -> Dict[str, int]:
    """
    Returns aggregated counts of alerts categorized by attack type and severity.
    """
    init_db(db_path)
    counts = {
        "total": 0,
        "port_scan": 0,
        "brute_force": 0,
        "flooding": 0,
        "high_severity": 0,
        "medium_severity": 0,
        "low_severity": 0
    }
    try:
        with get_connection(db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM alerts;")
            counts["total"] = cursor.fetchone()[0]

            cursor.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type;")
            for row in cursor.fetchall():
                atype, cnt = row[0], row[1]
                if "Port Scan" in atype:
                    counts["port_scan"] += cnt
                elif "Brute" in atype:
                    counts["brute_force"] += cnt
                elif "Flood" in atype:
                    counts["flooding"] += cnt

            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity;")
            for row in cursor.fetchall():
                sev, cnt = row[0].upper(), row[1]
                if "HIGH" in sev:
                    counts["high_severity"] += cnt
                elif "MED" in sev:
                    counts["medium_severity"] += cnt
                elif "LOW" in sev:
                    counts["low_severity"] += cnt
    except Exception as e:
        print(f"[ERROR] Error calculating alert counts: {e}")

    return counts


def export_alerts_to_csv(filepath: Optional[str] = None, db_path: Optional[str] = None) -> str:
    """
    Exports all stored security alerts to a CSV file and returns the CSV file path or raw string.
    """
    df = get_alerts_dataframe(limit=100000, db_path=db_path)
    if filepath is None:
        target_dir = os.path.dirname(get_db_path(db_path))
        filepath = os.path.join(target_dir, f"nids_alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

    df.to_csv(filepath, index=False)
    return filepath


def clear_all_alerts(db_path: Optional[str] = None) -> bool:
    """
    Deletes all records from the alerts table.
    """
    init_db(db_path)
    try:
        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts;")
            conn.commit()
            return True
    except Exception as e:
        print(f"[ERROR] Clearing alerts failed: {e}")
        return False
