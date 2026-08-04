from __future__ import annotations

import socket
import struct
from typing import Dict, Optional

from phishguard.config import Config
from phishguard.intel import IntelligenceHub


class SandboxProvider:
    def scan(self, filename: str, data: bytes) -> Dict[str, object]:
        raise NotImplementedError


class LocalHashSandbox(SandboxProvider):
    """Offline hash reputation check via the IntelligenceHub cache."""

    def __init__(self, intel: IntelligenceHub):
        self.intel = intel

    def scan(self, filename: str, data: bytes) -> Dict[str, object]:
        import hashlib
        sha = hashlib.sha256(data).hexdigest()
        verdict = self.intel.check_hash(sha)
        if verdict and verdict.get("malicious"):
            return {"malicious": True, "detail": verdict.get("source", "hash"), "sha256": sha}
        return {"malicious": False, "detail": "hash-clean", "sha256": sha}


class ClamAVSandbox(SandboxProvider):
    """Scans attachment bytes via ClamAV's INSTREAM protocol (no pyclamd dependency)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 3310, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout

    def scan(self, filename: str, data: bytes) -> Dict[str, object]:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall(b"zINSTREAM\0")
                chunk = 4096
                for i in range(0, len(data), chunk):
                    part = data[i:i + chunk]
                    sock.sendall(struct.pack("!L", len(part)) + part)
                sock.sendall(struct.pack("!L", 0))
                resp = b""
                while b"\0" not in resp:
                    buf = sock.recv(4096)
                    if not buf:
                        break
                    resp += buf
        except Exception:
            return {"malicious": False, "detail": "clamav-unavailable"}
        text = resp.decode("utf-8", "replace")
        if "FOUND" in text:
            sig = text.split(":", 1)[-1].replace("FOUND", "").strip()
            return {"malicious": True, "detail": sig}
        return {"malicious": False, "detail": "ok"}


class SandboxManager:
    def __init__(self, config: Config, intel: Optional[IntelligenceHub] = None):
        self.config = config
        if config.clamav_enabled:
            self.provider: SandboxProvider = ClamAVSandbox(config.clamav_host, config.clamav_port)
        else:
            self.provider = LocalHashSandbox(intel or IntelligenceHub(config))

    def scan(self, filename: str, data: bytes) -> Dict[str, object]:
        return self.provider.scan(filename, data)
