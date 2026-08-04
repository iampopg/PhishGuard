from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

from phishguard.models import ParsedEmail


class BehavioralStore:
    """Local, single-organization communication baseline for BEC anomaly detection.

    Honest scope: this captures relationship patterns *within the mailboxes you
    connect*. It has no cross-tenant network effect (unlike Abnormal/Defender at
    global scale), so it is a strong second-line signal, not a primary gate.
    """

    def __init__(self, db_path: str = "./behavioral.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS comms (
                sender_email TEXT,
                sender_domain TEXT,
                recipient TEXT,
                ts TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_comms_recipient ON comms(recipient);
            """
        )
        self._conn.commit()

    def record(self, parsed: ParsedEmail, timestamp: str = "") -> None:
        if not parsed.sender_email or not parsed.receiver_email:
            return
        from phishguard.models import now_iso
        self._conn.execute(
            "INSERT INTO comms (sender_email, sender_domain, recipient, ts) VALUES (?, ?, ?, ?)",
            (parsed.sender_email, parsed.sender_domain or "",
             parsed.receiver_email, timestamp or now_iso()),
        )
        self._conn.commit()

    def known_sender_for_recipient(self, recipient: str, sender_email: str) -> bool:
        if not recipient or not sender_email:
            return True
        row = self._conn.execute(
            "SELECT 1 FROM comms WHERE recipient = ? AND sender_email = ? LIMIT 1",
            (recipient, sender_email),
        ).fetchone()
        return row is not None

    def known_domain_for_recipient(self, recipient: str, sender_domain: str) -> bool:
        if not recipient or not sender_domain:
            return True
        row = self._conn.execute(
            "SELECT 1 FROM comms WHERE recipient = ? AND sender_domain = ? LIMIT 1",
            (recipient, sender_domain),
        ).fetchone()
        return row is not None

    def known_display_name_for_recipient(self, recipient: str, name: str) -> bool:
        if not recipient or not name:
            return True
        rows = self._conn.execute(
            "SELECT sender_email FROM comms WHERE recipient = ?", (recipient,)
        ).fetchall()
        names = {e["sender_email"].split("@")[0].lower() for e in rows if e["sender_email"]}
        return name.strip().lower() in names

    def close(self) -> None:
        self._conn.close()
