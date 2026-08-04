from __future__ import annotations

import imaplib

from phishguard.config import Config
from phishguard.mail.fetcher import MailFetcher


class FakeIMAP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.calls = []
        self._next = [
            [(b"1", b"From: a@b.com\nSubject: hi\n\nhello world")],
            [(b"2", b"From: c@d.com\nSubject: yo\n\nbody text")],
        ]

    def login(self, user, pw):
        self.calls.append(("login", user, pw))
        return ("OK", [b"ok"])

    def select(self, mailbox):
        self.calls.append(("select", mailbox))
        return ("OK", [b"2"])

    def search(self, *args):
        return ("OK", [b"1 2"])

    def uid(self, cmd, uid, *rest):
        if cmd == "FETCH":
            return ("OK", self._next.pop(0))
        if cmd == "STORE":
            self.calls.append(("store", uid))
            return ("OK", [b""])
        return ("OK", [b""])

    def close(self):
        self.calls.append(("close",))

    def logout(self):
        self.calls.append(("logout",))


def _cfg(password="valh odlj qmax feac"):
    c = Config()
    c.imap_server = "imap.gmail.com"
    c.imap_username = "sawdyk2@gmail.com"
    c.imap_password = password
    c.imap_mailbox = "INBOX"
    c.imap_use_ssl = True
    c.imap_port = 993
    c.imap_mark_read = False
    return c


def test_fetcher_uses_correct_config_attrs(monkeypatch):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    f = MailFetcher(_cfg())
    items = f.fetch_unseen(limit=10)
    assert len(items) == 2
    assert items[0][1].startswith(b"From: a@b.com")
    # login used the normalized (space-stripped) password
    login_call = next(c for c in f._conn.calls if c[0] == "login")
    assert login_call[1] == "sawdyk2@gmail.com"
    assert login_call[2] == "valhodljqmaxfeac"
    select_call = next(c for c in f._conn.calls if c[0] == "select")
    assert select_call[1] == "INBOX"
    # read-only by default: no STORE
    assert not any(c[0] == "store" for c in f._conn.calls)


def test_fetcher_marks_read_when_enabled(monkeypatch):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeIMAP)
    c = _cfg()
    c.imap_mark_read = True
    f = MailFetcher(c)
    f.fetch_unseen(limit=10)
    assert any(call[0] == "store" for call in f._conn.calls)
