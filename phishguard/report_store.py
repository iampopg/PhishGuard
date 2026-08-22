from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from phishguard.models import Report


class ReportStore:
    """SQLite-backed persistence for analysis reports, analyst feedback and baselines."""

    def __init__(self, db_path: str = "./phishguard.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                timestamp TEXT,
                verdict TEXT,
                risk_score INTEGER,
                message_id TEXT,
                data TEXT,
                raw BLOB
            );
            CREATE TABLE IF NOT EXISTS feedback (
                report_id TEXT,
                label TEXT,
                note TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS baselines (
                name TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(timestamp);
            """
        )
        # Migration: add raw column if missing from a previous schema version.
        cols = [r[1] for r in self._conn.execute("PRAGMA table_info(reports)").fetchall()]
        if "raw" not in cols:
            try:
                self._conn.execute("ALTER TABLE reports ADD COLUMN raw BLOB")
            except Exception:
                pass
        self._conn.commit()

    def save_report(self, report: Report, raw: bytes = None) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO reports "
            "(report_id, timestamp, verdict, risk_score, message_id, data, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (report.report_id, report.timestamp, report.verdict.value,
             report.risk_score, report.source.get("message_id"),
             json.dumps(report.to_dict(), default=str), raw),
        )
        self._conn.commit()

    def get_raw(self, report_id: str) -> Optional[bytes]:
        row = self._conn.execute(
            "SELECT raw FROM reports WHERE report_id = ?", (report_id,)).fetchone()
        return row["raw"] if row and row["raw"] else None

    def list_report_ids(self, limit: int = 10000) -> List[str]:
        rows = self._conn.execute(
            "SELECT report_id FROM reports ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [r["report_id"] for r in rows]

    def update_report(self, report: Report) -> None:
        self._conn.execute(
            "UPDATE reports SET timestamp = ?, verdict = ?, risk_score = ?, data = ? WHERE report_id = ?",
            (report.timestamp, report.verdict.value, report.risk_score,
             json.dumps(report.to_dict(), default=str), report.report_id))
        self._conn.commit()

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT data FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_reports(self, limit: int = 100, verdict: Optional[str] = None) -> List[Dict[str, Any]]:
        if verdict:
            rows = self._conn.execute(
                "SELECT data FROM reports WHERE verdict = ? ORDER BY timestamp DESC LIMIT ?",
                (verdict, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM reports ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def add_feedback(self, report_id: str, label: str, note: str = "", timestamp: str = "") -> None:
        from phishguard.models import now_iso
        self._conn.execute(
            "INSERT INTO feedback (report_id, label, note, timestamp) VALUES (?, ?, ?, ?)",
            (report_id, label, note, timestamp or now_iso()),
        )
        self._conn.commit()

    def get_feedback(self, report_id: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT label, note, timestamp FROM feedback WHERE report_id = ?", (report_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def save_baseline(self, name: str, value: Any) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO baselines (name, value) VALUES (?, ?)",
            (name, json.dumps(value, default=str)),
        )
        self._conn.commit()

    def load_baseline(self, name: str) -> Any:
        row = self._conn.execute(
            "SELECT value FROM baselines WHERE name = ?", (name,)
        ).fetchone()
        return json.loads(row["value"]) if row else None

    def close(self) -> None:
        self._conn.close()
