from __future__ import annotations

from typing import Any, Dict, Optional

import requests

_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider:
    """AbuseIPDB — IP/domain abuse confidence scoring."""

    name = "abuseipdb"

    def __init__(self, api_key: str = "", timeout: int = 15, verify_ssl: bool = True):
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _headers(self) -> Dict[str, str]:
        return {"Key": self.api_key, "Accept": "application/json"}

    def _get(self, path: str, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None
        try:
            r = requests.get(f"{_BASE}{path}", headers=self._headers(), params=params,
                             timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        data = self._get("/check", {"ipAddress": ip, "maxAgeInDays": "90"})
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        info = data.get("data", {}) or {}
        score = info.get("abuseConfidenceScore", 0)
        return {
            "malicious": score >= 50,
            "source": self.name,
            "ip": ip,
            "abuse_confidence_score": score,
            "total_reports": info.get("totalReports", 0),
            "last_reported": info.get("lastReportedAt"),
            "country": info.get("countryCode"),
            "usage_type": info.get("usageType"),
            "isp": info.get("isp"),
            "is_tor": info.get("isTor"),
        }

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        data = self._get("/check-domain", {"domain": domain, "maxAgeInDays": "90"})
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        info = data.get("data", {}) or {}
        score = info.get("abuseConfidenceScore", 0)
        return {
            "malicious": score >= 50,
            "source": self.name,
            "domain": domain,
            "abuse_confidence_score": score,
            "total_reports": info.get("totalReports", 0),
            "last_reported": info.get("lastReportedAt"),
        }

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        return {"malicious": False, "source": self.name, "detail": "url_lookup_unsupported"}

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        return {"malicious": False, "source": self.name, "detail": "hash_lookup_unsupported"}
