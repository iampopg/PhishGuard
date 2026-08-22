from __future__ import annotations

from typing import Any, Dict, Optional

import requests

_BASE = "https://urlscan.io/api/v1"


class UrlscanProvider:
    """urlscan.io — sandboxed URL scanning with public search archive."""

    name = "urlscan"

    def __init__(self, api_key: str = "", timeout: int = 15, verify_ssl: bool = True):
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _headers(self) -> Dict[str, str]:
        return {"api-key": self.api_key} if self.api_key else {}

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        try:
            r = requests.get(f"{_BASE}{path}", headers=self._headers(), params=params,
                             timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    def _verdict(self, result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not result:
            return {"malicious": False, "source": self.name, "detail": "no_match"}
        verdicts = result.get("verdicts", {})
        overall = verdicts.get("overall", {}) or {}
        malicious = bool(overall.get("malicious"))
        score = overall.get("score", 0)
        brands = result.get("lists", {}).get("brands", []) if isinstance(result.get("lists"), dict) else []
        return {
            "malicious": malicious,
            "source": self.name,
            "score": score,
            "url": result.get("page", {}).get("url") if isinstance(result.get("page"), dict) else None,
            "domain": result.get("page", {}).get("domain") if isinstance(result.get("page"), dict) else None,
            "ip": result.get("page", {}).get("ip") if isinstance(result.get("page"), dict) else None,
            "brands": brands,
            "screenshot": result.get("task", {}).get("screenshotURL") if isinstance(result.get("task"), dict) else None,
        }

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        res = self._get("/search/", {"q": f"page.url:{url}", "size": 1})
        if not res:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        results = res.get("results", [])
        if not results:
            return {"malicious": False, "source": self.name, "detail": "no_match"}
        return self._verdict(results[0])

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        res = self._get("/search/", {"q": f"domain:{domain}", "size": 1})
        if not res:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        results = res.get("results", [])
        if not results:
            return {"malicious": False, "source": self.name, "detail": "no_match"}
        return self._verdict(results[0])

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        res = self._get("/search/", {"q": f"page.ip:{ip}", "size": 1})
        if not res:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        results = res.get("results", [])
        if not results:
            return {"malicious": False, "source": self.name, "detail": "no_match"}
        return self._verdict(results[0])

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        return {"malicious": False, "source": self.name, "detail": "hash_lookup_unsupported"}

    def submit(self, url: str, visibility: str = "public") -> Optional[str]:
        """Submit a URL for scanning. Returns the scan uuid or None."""
        if not self.api_key:
            return None
        try:
            r = requests.post(f"{_BASE}/scan/", headers=self._headers(),
                              json={"url": url, "visibility": visibility},
                              timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json().get("uuid")
        except Exception:
            return None
        return None

    def result(self, uuid: str) -> Optional[Dict[str, Any]]:
        return self._get(f"/result/{uuid}/")

    def screenshot(self, uuid: str) -> Optional[bytes]:
        try:
            r = requests.get(f"{_BASE}/screenshots/{uuid}.png", timeout=self.timeout,
                             verify=self.verify_ssl)
            if r.status_code == 200:
                return r.content
        except Exception:
            return None
        return None

    def dom(self, uuid: str) -> Optional[str]:
        try:
            r = requests.get(f"{_BASE}/dom/{uuid}/", timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.text
        except Exception:
            return None
        return None
