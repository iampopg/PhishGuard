from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

CACHE_VERSION = 1


def _vt_verdict(data: dict) -> dict:
    """Parse a VirusTotal API response into a normalized verdict.

    VT returns HTTP 200 for every scanned URL/hash, clean or not. A URL is only
    malicious when its community scanners actually flag it, so we read the
    analysis stats and require at least one malicious detection.
    """
    attrs = (data or {}).get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
    stats = attrs.get("last_analysis_stats", {}) or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) if stats else 0
    engines = []
    results = attrs.get("last_analysis_results", {}) or {}
    for engine, r in results.items():
        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"):
            engines.append({"engine": engine, "category": r.get("category"), "result": r.get("result")})
    return {
        "malicious": malicious > 0,
        "source": "virustotal",
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "engines": engines[:15],
        "permalink": attrs.get("permalink"),
    }


class IntelligenceHub:
    """Threat-intel lookups with graceful offline fallback.

    Works with zero external APIs: defaults to a local blocklist cache.
    Optional VirusTotal enrichment when enabled and an API key is set.
    """

    def __init__(self, config, cache_dir: Path = Path(".cache/intel")):
        self.config = config
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._hash_cache: Dict[str, dict] = {}
        self._url_cache: Dict[str, dict] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        for name, store in (("urls.json", self._url_cache), ("hashes.json", self._hash_cache)):
            p = self.cache_dir / name
            if p.exists():
                try:
                    store.update(json.loads(p.read_text()))
                except Exception:
                    pass

    def _save_cache(self) -> None:
        (self.cache_dir / "urls.json").write_text(json.dumps(self._url_cache))
        (self.cache_dir / "hashes.json").write_text(json.dumps(self._hash_cache))

    def add_url_verdict(self, url: str, verdict: dict) -> None:
        self._url_cache[url] = verdict
        self._save_cache()

    def add_hash_verdict(self, sha256: str, verdict: dict) -> None:
        self._hash_cache[sha256.lower()] = verdict
        self._save_cache()

    def check_url(self, url: str) -> Optional[dict]:
        if url in self._url_cache:
            return self._url_cache[url]
        res = self._vt_url(url) if getattr(self.config, "vt_enabled", False) else None
        if res is None:
            res = {"malicious": False, "source": "none"}
        self._url_cache[url] = res
        return res

    def check_hash(self, sha256: str) -> Optional[dict]:
        sha256 = sha256.lower()
        if sha256 in self._hash_cache:
            return self._hash_cache[sha256]
        res = self._vt_hash(sha256) if getattr(self.config, "vt_enabled", False) else None
        if res is None:
            res = {"malicious": False, "source": "none"}
        self._hash_cache[sha256] = res
        return res

    def _vt_url(self, url: str) -> Optional[dict]:
        try:
            import requests  # type: ignore
        except Exception:
            return None
        key = getattr(self.config, "vt_api_key", "")
        if not key:
            return None
        try:
            r = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": key},
                data={"url": url}, timeout=10,
            )
            if r.status_code != 200:
                return None
            return _vt_verdict(r.json())
        except Exception:
            return None

    def _vt_hash(self, sha256: str) -> Optional[dict]:
        try:
            import requests  # type: ignore
        except Exception:
            return None
        key = getattr(self.config, "vt_api_key", "")
        if not key:
            return None
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": key}, timeout=10,
            )
            if r.status_code != 200:
                return None
            return _vt_verdict(r.json())
        except Exception:
            return None
