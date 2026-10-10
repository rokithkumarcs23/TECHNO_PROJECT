"""
Alert Manager Module for Network Intrusion Detection System (NIDS).
Coordinates threat detection events, synchronizes with the persistent SQLite database,
provides in-memory filtering, statistics aggregation, and alert formatting for dashboard rendering.
"""

from typing import List, Dict, Any, Optional
import pandas as pd
from modules.database import (
    insert_alert,
    insert_alerts_batch,
    get_alerts,
    get_alerts_dataframe,
    get_alert_counts,
    export_alerts_to_csv,
    clear_all_alerts
)


class AlertManager:
    """
    Coordinates security event lifecycle, database synchronization,
    and dashboard presentation formatting.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._session_alerts: List[Dict[str, Any]] = []

    def record_alerts(self, alerts: List[Dict[str, Any]], persist: bool = True) -> int:
        """
        Receives new alerts from the detection engine, stores them in the active session,
        and persists them to SQLite.
        """
        if not alerts:
            return 0

        self._session_alerts.extend(alerts)

        if persist:
            return insert_alerts_batch(alerts, db_path=self.db_path)
        return len(alerts)

    def get_session_alerts(self) -> List[Dict[str, Any]]:
        """
        Returns all alerts recorded during the current dashboard session.
        """
        return list(self._session_alerts)

    def get_persisted_alerts(
        self,
        limit: int = 500,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves filtered alerts from the SQLite database.
        """
        return get_alerts(
            limit=limit,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            start_time=start_time,
            end_time=end_time,
            db_path=self.db_path
        )

    def get_alerts_df(
        self,
        limit: int = 1000,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> pd.DataFrame:
        """
        Retrieves alerts as a Pandas DataFrame.
        """
        return get_alerts_dataframe(
            limit=limit,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            db_path=self.db_path
        )

    def get_summary_metrics(self) -> Dict[str, int]:
        """
        Fetches aggregated attack and severity counts from the database.
        """
        return get_alert_counts(db_path=self.db_path)

    def clear_database(self) -> bool:
        """
        Clears both database records and current session in-memory alerts.
        """
        self._session_alerts.clear()
        return clear_all_alerts(db_path=self.db_path)

    def export_csv(self, filepath: Optional[str] = None) -> str:
        """
        Exports all persisted alerts to a CSV file.
        """
        return export_alerts_to_csv(filepath=filepath, db_path=self.db_path)
