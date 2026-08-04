from __future__ import annotations

import csv
import urllib.request
from typing import List

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

_HEADERS = {"User-Agent": "PhishGuard/1.0 (+https://github.com/ran-corp/PhishGuard)"}


def _get(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


class FeedManager:
    """Pulls free threat-intel feeds into the local IntelligenceHub cache.

    Network is optional: failures are swallowed so the engine stays offline-first.
    """

    def __init__(self, max_entries: int = 5000):
        self.max_entries = max_entries

    def update_urlhaus(self, intel) -> int:
        try:
            data = _get(URLHAUS_CSV)
        except Exception:
            return 0
        count = 0
        for line in data.splitlines():
            if not line or line.startswith("#"):
                continue
            try:
                row = next(csv.reader([line]))
            except Exception:
                continue
            if len(row) < 3:
                continue
            url = row[2].strip()
            if not url:
                continue
            intel.add_url_verdict(url, {"malicious": True, "source": "urlhaus"})
            count += 1
            if count >= self.max_entries:
                break
        return count

    def update_openphish(self, intel) -> int:
        try:
            data = _get(OPENPHISH_FEED)
        except Exception:
            return 0
        count = 0
        for line in data.splitlines():
            url = line.strip()
            if not url:
                continue
            intel.add_url_verdict(url, {"malicious": True, "source": "openphish"})
            count += 1
            if count >= self.max_entries:
                break
        return count

    def update_all(self, intel) -> dict:
        return {
            "urlhaus": self.update_urlhaus(intel),
            "openphish": self.update_openphish(intel),
        }
