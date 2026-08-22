from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol


class ThreatIntelligenceProvider(Protocol):
    """Protocol each threat-intelligence provider implements.

    Every method returns a normalized verdict dict and NEVER raises into the
    analysis path: network/timeout/auth failures degrade to a benign verdict
    carrying an ``error`` field so callers can see what happened.
    """

    name: str

    def check_url(self, url: str) -> Optional[Dict[str, Any]]: ...

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]: ...

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]: ...

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]: ...


def _benign(source: str, error: Optional[str] = None) -> Dict[str, Any]:
    d: Dict[str, Any] = {"malicious": False, "source": source}
    if error:
        d["error"] = error
    return d
