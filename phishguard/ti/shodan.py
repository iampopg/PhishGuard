from __future__ import annotations

from typing import Any, Dict, Optional

import requests

_BASE = "https://api.shodan.io"


class ShodanProvider:
    """Shodan — host/DNS reconnaissance for sender IPs and domains."""

    name = "shodan"

    def __init__(self, api_key: str = "", timeout: int = 15, verify_ssl: bool = True):
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _get(self, path: str, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None
        try:
            p = dict(params)
            p["key"] = self.api_key
            r = requests.get(f"{_BASE}{path}", params=p, timeout=self.timeout, verify=self.verify_ssl)
            if r.status_code == 200:
                return r.json()
        except Exception:
            return None
        return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        data = self._get(f"/shodan/host/{ip}", {})
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        vulns = data.get("vulns", []) or []
        return {
            "malicious": bool(vulns),
            "source": self.name,
            "ip": ip,
            "org": data.get("org"),
            "os": data.get("os"),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "vulns": list(vulns)[:10],
            "tags": data.get("tags", []),
        }

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        data = self._get(f"/dns/domain/{domain}", {})
        if not data:
            return {"malicious": False, "source": self.name, "error": "lookup_failed"}
        return {
            "malicious": False,
            "source": self.name,
            "domain": domain,
            "subdomains": data.get("subdomains", []),
            "data_points": len(data.get("data", []) or []),
        }

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        return {"malicious": False, "source": self.name, "detail": "url_lookup_unsupported"}

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        return {"malicious": False, "source": self.name, "detail": "hash_lookup_unsupported"}
