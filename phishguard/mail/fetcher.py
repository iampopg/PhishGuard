from __future__ import annotations

import imaplib
from typing import List, Tuple

from phishguard.config import Config


class MailFetcher:
    def __init__(self, config: Config):
        self.config = config
        self._conn = None

    def connect(self) -> None:
        host = self.config.imap_server
        port = self.config.imap_port or (993 if self.config.imap_use_ssl else 143)
        if self.config.imap_use_ssl:
            self._conn = imaplib.IMAP4_SSL(host, port)
        else:
            self._conn = imaplib.IMAP4(host, port)
        sock = getattr(self._conn, "sock", None)
        if sock is not None:
            sock.settimeout(self.config.imap_timeout)
        # App passwords are sometimes pasted in grouped form ("abcd efgh ..."); strip spaces.
        password = (self.config.imap_password or "").replace(" ", "")
        self._conn.login(self.config.imap_username, password)
        self._conn.select(self.config.imap_mailbox or "INBOX")

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.close()
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def fetch_unseen(self, limit: int = 50) -> List[Tuple[str, bytes]]:
        return self._fetch("UNSEEN", limit)

    def fetch_recent(self, limit: int = 50) -> List[Tuple[str, bytes]]:
        return self._fetch("RECENT", limit)

    def _fetch(self, criterion: str, limit: int) -> List[Tuple[str, bytes]]:
        if not self._conn:
            self.connect()
        typ, data = self._conn.search(None, criterion)
        if typ != "OK":
            return []
        uids = data[0].split()[-limit:] if data and data[0] else []
        out = []
        mark_read = getattr(self.config, "imap_mark_read", False)
        for uid in uids:
            typ, msg_data = self._conn.uid("FETCH", uid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            if not isinstance(raw, bytes):
                continue
            out.append((uid.decode() if isinstance(uid, bytes) else str(uid), raw))
            if mark_read:
                self._conn.uid("STORE", uid, "+FLAGS", "\\Seen")
        return out
