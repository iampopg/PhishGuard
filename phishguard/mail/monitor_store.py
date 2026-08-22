from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import List, Optional


class MonitorStore:
    """Tracks which mailbox UIDs the monitor has already processed.

    IMAP UIDs are only stable alongside UIDVALIDITY; if it changes (e.g. mailbox
    rebuilt) we discard the set and reprocess from scratch. Persisted to SQLite so
    the monitor survives restarts without re-analyzing the same mail.
    """

    def __init__(self, db_path: str = "./reports/monitor.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS processed (
                uidvalidity TEXT NOT NULL,
                uid TEXT NOT NULL,
                report_id TEXT,
                processed_at TEXT,
                PRIMARY KEY (uidvalidity, uid)
            );
            """
        )
        self._conn.commit()

    def uidvalidity(self) -> Optional[str]:
        cur = self._conn.execute("SELECT value FROM state WHERE key = ?", ("uidvalidity",))
        row = cur.fetchone()
        return row[0] if row else None

    def set_uidvalidity(self, validity: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO state(key, value) VALUES (?, ?)", ("uidvalidity", validity))
        self._conn.commit()

    def update_uidvalidity(self, validity: str) -> bool:
        """Returns True if validity changed (caller should clear processed UIDs)."""
        prev = self.uidvalidity()
        if prev != validity:
            self.set_uidvalidity(validity)
            return True
        return False

    def is_processed(self, uidvalidity: str, uid: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM processed WHERE uidvalidity = ? AND uid = ?", (uidvalidity, uid))
        return cur.fetchone() is not None

    def unprocessed(self, uids: List[str], uidvalidity: str) -> List[str]:
        return [u for u in uids if not self.is_processed(uidvalidity, u)]

    def mark_processed(self, uidvalidity: str, uid: str, report_id: str, ts: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO processed(uidvalidity, uid, report_id, processed_at) VALUES (?, ?, ?, ?)",
            (uidvalidity, uid, report_id, ts))
        self._conn.commit()

    def reset(self) -> None:
        self._conn.execute("DELETE FROM processed")
        self._conn.execute("DELETE FROM state")
        self._conn.commit()

    def stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) FROM processed").fetchone()[0]
        last = self._conn.execute(
            "SELECT MAX(processed_at) FROM processed").fetchone()[0]
        return {"processed": total, "uidvalidity": self.uidvalidity(), "last": last}

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
