from __future__ import annotations

from pathlib import Path
from typing import Dict

from phishguard.config import Config

DEFAULT_ENV = ".env"


def load_env_dict(path: str = DEFAULT_ENV) -> Dict[str, str]:
    d: Dict[str, str] = {}
    p = Path(path)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def update_env(updates: Dict[str, str], path: str = DEFAULT_ENV) -> None:
    """Update KEY=VALUE pairs in place, preserving comments and order; append new keys."""
    p = Path(path)
    lines = p.read_text().splitlines() if p.exists() else []
    seen = {}
    for i, l in enumerate(lines):
        if "=" in l and not l.strip().startswith("#"):
            seen[l.split("=", 1)[0].strip()] = i
    out = list(lines)
    for k, v in updates.items():
        if k in seen:
            out[seen[k]] = f"{k}={v}"
        else:
            out.append(f"{k}={v}")
    p.write_text("\n".join(out) + "\n")
    reload_env()


def reload_env() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except Exception:
        pass


def current_config() -> Config:
    reload_env()
    return Config.load()
