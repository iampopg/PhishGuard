from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import List


@dataclass
class OrgProfile:
    protected_domains: List[str] = field(default_factory=list)
    vip_names: List[str] = field(default_factory=list)
    brand_keywords: List[str] = field(default_factory=list)
    brand_domains: List[str] = field(default_factory=list)
    trusted_domains: List[str] = field(default_factory=list)

    def normalize(self) -> None:
        self.protected_domains = [d.lower().strip() for d in self.protected_domains if d.strip()]
        self.brand_domains = [d.lower().strip() for d in self.brand_domains if d.strip()]
        self.trusted_domains = [d.lower().strip() for d in self.trusted_domains if d.strip()]
        self.vip_names = [n.strip().lower() for n in self.vip_names if n.strip()]
        self.brand_keywords = [k.strip().lower() for k in self.brand_keywords if k.strip()]

    @classmethod
    def load(cls, path: str = "", trusted: List[str] = None) -> "OrgProfile":
        prof = cls(trusted_domains=list(trusted or []))
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                prof.protected_domains = data.get("protected_domains", [])
                prof.vip_names = data.get("vip_names", [])
                prof.brand_keywords = data.get("brand_keywords", [])
                prof.brand_domains = data.get("brand_domains", [])
                prof.trusted_domains = data.get("trusted_domains", prof.trusted_domains)
            except (json.JSONDecodeError, OSError):
                pass
        prof.normalize()
        return prof

    def is_trusted(self, domain: str) -> bool:
        d = (domain or "").lower()
        return d in self.trusted_domains

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
