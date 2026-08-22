from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from phishguard.config import Config
from phishguard.forensics.ioc import IOCs
from phishguard.ti.abuseipdb import AbuseIPDBProvider
from phishguard.ti.base import ThreatIntelligenceProvider, _benign
from phishguard.ti.misp import MISPProvider
from phishguard.ti.otx import OTXProvider
from phishguard.ti.shodan import ShodanProvider
from phishguard.ti.urlscan import UrlscanProvider


class ThreatIntelligenceManager:
    """Orchestrates enabled threat-intelligence providers.

    Lookups are cached by (provider, kind, value) for ``ttl`` seconds so repeat
    enrichment is instant and offline-safe. Provider failures are aggregated into
    an ``errors`` list rather than raised into the analysis path.
    """

    def __init__(self, config: Config, providers: Optional[List[ThreatIntelligenceProvider]] = None,
                 ttl: Optional[int] = None):
        self.config = config
        self.ttl = ttl if ttl is not None else int(getattr(config, "ti_cache_ttl", 3600))
        self._cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
        self.providers = providers or self._default_providers(config)

    @staticmethod
    def _default_providers(config: Config) -> List[ThreatIntelligenceProvider]:
        providers: List[ThreatIntelligenceProvider] = []
        timeout = int(getattr(config, "url_deep_timeout", 15))
        if getattr(config, "urlscan_enabled", False):
            providers.append(UrlscanProvider(getattr(config, "urlscan_api_key", ""), timeout=timeout))
        if getattr(config, "shodan_enabled", False):
            providers.append(ShodanProvider(getattr(config, "shodan_api_key", ""), timeout=timeout))
        if getattr(config, "otx_enabled", False):
            providers.append(OTXProvider(getattr(config, "otx_api_key", ""), timeout=timeout))
        if getattr(config, "misp_enabled", False):
            providers.append(MISPProvider(getattr(config, "misp_url", ""),
                                          getattr(config, "misp_api_key", ""),
                                          timeout=timeout,
                                          verify_ssl=bool(getattr(config, "misp_verify_ssl", True))))
        if getattr(config, "abuseipdb_enabled", False):
            providers.append(AbuseIPDBProvider(getattr(config, "abuseipdb_api_key", ""), timeout=timeout))
        return providers

    @property
    def enabled_names(self) -> List[str]:
        return [p.name for p in self.providers]

    def _cache_key(self, provider: str, kind: str, value: str) -> str:
        return f"{provider}:{kind}:{value}".lower()

    def _cached(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self._cache.get(key)
        if entry and (time.time() - entry[0]) < self.ttl:
            return entry[1]
        return None

    def _store(self, key: str, verdict: Dict[str, Any]) -> None:
        self._cache[key] = (time.time(), verdict)

    @staticmethod
    def _safe(fn):
        def wrapper(self, *a, **k):
            try:
                return fn(self, *a, **k)
            except Exception as e:
                return {"malicious": False, "source": "unknown", "error": f"{type(e).__name__}: {e}"}
        return wrapper

    def _lookup(self, provider: ThreatIntelligenceProvider, kind: str, value: str) -> Dict[str, Any]:
        key = self._cache_key(provider.name, kind, value)
        hit = self._cached(key)
        if hit is not None:
            return hit
        fn = {
            "url": provider.check_url,
            "domain": provider.check_domain,
            "ip": provider.check_ip,
            "hash": provider.check_hash,
        }.get(kind)
        verdict = fn(value) if fn else _benign(provider.name, "unsupported_kind")
        verdict = verdict if verdict is not None else _benign(provider.name, "null_result")
        if "error" not in verdict and "detail" not in verdict:
            verdict.setdefault("malicious", False)
        self._store(key, verdict)
        return verdict

    def enrich(self, iocs: IOCs) -> Dict[str, Any]:
        """Enrich all extracted observables across providers. Never raises."""
        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        hits = 0
        total = 0

        seen_urls = list(dict.fromkeys(iocs.urls))
        seen_domains = list(dict.fromkeys(iocs.domains))
        seen_ips = list(dict.fromkeys(iocs.ips))
        seen_hashes = list(dict.fromkeys(iocs.sha256))

        for prov in self.providers:
            for url in seen_urls:
                v = self._lookup(prov, "url", url)
                total += 1
                if v.get("malicious"):
                    hits += 1
                results.append({"kind": "url", "value": url, **v})
                if "error" in v:
                    errors.append({"provider": prov.name, "kind": "url", "value": url, "error": v["error"]})
            for domain in seen_domains:
                v = self._lookup(prov, "domain", domain)
                total += 1
                if v.get("malicious"):
                    hits += 1
                results.append({"kind": "domain", "value": domain, **v})
                if "error" in v:
                    errors.append({"provider": prov.name, "kind": "domain", "value": domain, "error": v["error"]})
            for ip in seen_ips:
                v = self._lookup(prov, "ip", ip)
                total += 1
                if v.get("malicious"):
                    hits += 1
                results.append({"kind": "ip", "value": ip, **v})
                if "error" in v:
                    errors.append({"provider": prov.name, "kind": "ip", "value": ip, "error": v["error"]})
            for sha in seen_hashes:
                v = self._lookup(prov, "hash", sha)
                total += 1
                if v.get("malicious"):
                    hits += 1
                results.append({"kind": "hash", "value": sha, **v})
                if "error" in v:
                    errors.append({"provider": prov.name, "kind": "hash", "value": sha, "error": v["error"]})

        return {
            "providers": self.enabled_names,
            "results": results,
            "summary": {"checks": total, "malicious": hits, "benign": total - hits, "errors": len(errors)},
            "errors": errors,
        }
