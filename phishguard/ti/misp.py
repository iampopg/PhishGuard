from __future__ import annotations

from typing import Any, Dict, Optional

import requests


class MISPProvider:
    """MISP — correlate observables against a MISP threat-sharing instance."""

    name = "misp"

    def __init__(self, url: str = "", api_key: str = "", timeout: int = 15, verify_ssl: bool = True):
        self.url = (url or "").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = self.api_key
        return h

    def _search(self, attr_type: str, value: str) -> Optional[Dict[str, Any]]:
        if not self.url or not self.api_key:
            return None
        try:
            r = requests.post(f"{self.url}/attributes/restSearch",
                              headers=self._headers(),
                              json={"returnFormat": "json", "type": attr_type, "value": value},
                              timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    def _result(self, value: str, data: Optional[Dict[str, Any]], malicious: bool) -> Dict[str, Any]:
        out: Dict[str, Any] = {"malicious": malicious, "source": self.name, "value": value}
        if data is None:
            out["error"] = "lookup_failed"
            return out
        attrs = (data.get("response") or {}).get("Attribute", []) or []
        out["attributes"] = len(attrs)
        out["events"] = sorted({a.get("event_id") for a in attrs if a.get("event_id")})[:10]
        out["tags"] = sorted({t.get("name") for a in attrs for t in (a.get("Tag", []) or [])
                              if t.get("name")})[:10]
        return out

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        data = self._search("url", url)
        attrs = ((data or {}).get("response") or {}).get("Attribute", []) or []
        return self._result(url, data, bool(attrs))

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        data = self._search("domain", domain)
        attrs = ((data or {}).get("response") or {}).get("Attribute", []) or []
        return self._result(domain, data, bool(attrs))

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        data = self._search("ip-dst", ip)
        attrs = ((data or {}).get("response") or {}).get("Attribute", []) or []
        return self._result(ip, data, bool(attrs))

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        data = self._search("sha256", sha256)
        attrs = ((data or {}).get("response") or {}).get("Attribute", []) or []
        return self._result(sha256, data, bool(attrs))
