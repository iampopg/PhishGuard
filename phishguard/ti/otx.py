from __future__ import annotations

from typing import Any, Dict, Optional

import requests

_BASE = "https://otx.alienvault.com/api/v1"


class OTXProvider:
    """AlienVault OTX — community threat-intel pulses for IPs, domains, hashes."""

    name = "otx"

    def __init__(self, api_key: str = "", timeout: int = 15, verify_ssl: bool = True):
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _headers(self) -> Dict[str, str]:
        return {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

    def _get(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            r = requests.get(f"{_BASE}{path}", headers=self._headers(), timeout=self.timeout,
                             verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    def _pulse_count(self, section: Dict[str, Any]) -> int:
        if not section:
            return 0
        return section.get("count", 0) or 0

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        data = self._get(f"/indicators/IPv4/{ip}/general")
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        reps = self._get(f"/indicators/IPv4/{ip}/reputation")
        pulse = reps.get("reputation", {}) if reps else None
        count = pulse.get("count") if isinstance(pulse, dict) else None
        return {
            "malicious": bool(count),
            "source": self.name,
            "ip": ip,
            "pulse_count": count,
            "type": data.get("type"),
            "country": data.get("country_name"),
            "asn": data.get("asn"),
            "sections": data.get("sections", []),
        }

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        data = self._get(f"/indicators/domain/{domain}/general")
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        pulse_info = data.get("pulse_info", {}) or {}
        count = pulse_info.get("count", 0)
        return {
            "malicious": bool(count),
            "source": self.name,
            "domain": domain,
            "pulse_count": count,
            "tags": data.get("pulse_info", {}).get("tags", []) if count else [],
            "sections": data.get("sections", []),
            "hostname": data.get("hostname"),
            "flags": data.get("flags"),
        }

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        data = self._get(f"/indicators/url/{requests.utils.quote(url, safe='')}/general")
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        pulse_info = data.get("pulse_info", {}) or {}
        count = pulse_info.get("count", 0)
        httpcode = self._get(f"/indicators/url/{requests.utils.quote(url, safe='')}/http")
        return {
            "malicious": bool(count),
            "source": self.name,
            "url": url,
            "pulse_count": count,
            "tags": pulse_info.get("tags", []) if count else [],
            "has_http": bool(httpcode),
        }

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        data = self._get(f"/indicators/file/{sha256}/general")
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        pulse_info = data.get("pulse_info", {}) or {}
        count = pulse_info.get("count", 0)
        return {
            "malicious": bool(count),
            "source": self.name,
            "sha256": sha256,
            "pulse_count": count,
            "tags": pulse_info.get("tags", []) if count else [],
            "analysis": bool(data.get("analysis")),
        }
