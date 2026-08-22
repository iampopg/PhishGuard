from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class EvidenceStore:
    """Stores raw artifacts for a report under ``{report_dir}/evidence/<id>/``.

    Best-effort: every write is guarded so analysis never breaks on evidence I/O.
    """

    def __init__(self, base_dir: str = "./reports"):
        self.base_dir = Path(base_dir)
        self.evidence_dir = self.base_dir / "evidence"

    def _dir(self, report_id: str) -> Path:
        safe = "".join(c for c in (report_id or "unknown") if c.isalnum() or c in "-_")
        d = self.evidence_dir / (safe or "unknown")
        return d

    def store_artifacts(
        self,
        report_id: str,
        raw: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
        report: Optional[Dict[str, Any]] = None,
        screenshot: Optional[bytes] = None,
        dom: Optional[str] = None,
    ) -> List[str]:
        d = self._dir(report_id)
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            return []
        written: List[str] = []
        if raw:
            try:
                (d / "raw.eml").write_bytes(raw)
                written.append("raw.eml")
            except Exception:
                pass
        if headers:
            try:
                (d / "headers.json").write_text(json.dumps(headers, indent=2, default=str))
                written.append("headers.json")
            except Exception:
                pass
        if body_text:
            try:
                (d / "body.txt").write_text(body_text)
                written.append("body.txt")
            except Exception:
                pass
        if body_html:
            try:
                (d / "body.html").write_text(body_html)
                written.append("body.html")
            except Exception:
                pass
        if report:
            try:
                (d / "report.json").write_text(json.dumps(report, indent=2, default=str))
                written.append("report.json")
            except Exception:
                pass
        if screenshot:
            try:
                (d / "screenshot.png").write_bytes(screenshot)
                written.append("screenshot.png")
            except Exception:
                pass
        if dom:
            try:
                (d / "dom.html").write_text(dom)
                written.append("dom.html")
            except Exception:
                pass
        return written

    def list_artifacts(self, report_id: str) -> List[Dict[str, Any]]:
        d = self._dir(report_id)
        if not d.exists():
            return []
        out = []
        for p in sorted(d.iterdir()):
            if p.is_file():
                out.append({"name": p.name, "size": p.stat().st_size})
        return out

    def get_artifact(self, report_id: str, name: str) -> Optional[Path]:
        if any(c in name for c in "/\\"):
            return None
        d = self._dir(report_id)
        p = d / name
        if p.exists() and p.is_file():
            return p
        return None

    def has_evidence(self, report_id: str) -> bool:
        return self._dir(report_id).exists()
