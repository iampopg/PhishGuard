from __future__ import annotations

from typing import Dict, List

from phishguard.config import Config
from phishguard.models import Report


class RemediationManager:
    """Post-delivery remediation. Honest scope: this is NOT a pre-delivery gateway.

    Actions run after a message has been delivered (move to junk/quarantine,
    soft-delete, notify SOC). M365 (Graph) and Gmail (API) are optional and
    require credentials; everything degrades to a no-op when not configured.
    """

    def __init__(self, config: Config):
        self.config = config

    @property
    def enabled(self) -> bool:
        return self.config.remediation_enabled

    def apply(self, report: Report) -> List[Dict[str, str]]:
        if not self.enabled:
            return []
        results: List[Dict[str, str]] = []
        provider = self.config.remediation_provider
        for action in report.recommended_actions:
            if action in ("quarantine", "delete_if_confirmed"):
                ok = self._remove(provider, report)
                results.append({"action": action, "status": "done" if ok else "skipped"})
            elif action == "notify_soc":
                ok = self._notify(provider, report)
                results.append({"action": action, "status": "done" if ok else "skipped"})
            else:
                results.append({"action": action, "status": "ignored"})
        return results

    def _remove(self, provider: str, report: Report) -> bool:
        if provider == "m365":
            return self._m365_move(report, to_junk=True)
        if provider == "gmail":
            return self._gmail_trash(report)
        return False

    def _notify(self, provider: str, report: Report) -> bool:
        url = self.config.export_webhook_url
        if url:
            try:
                import requests  # type: ignore
                requests.post(url, json=report.to_dict(), timeout=10)
                return True
            except Exception:
                return False
        return False

    def _m365_token(self) -> str:
        import requests  # type: ignore
        c = self.config
        r = requests.post(
            f"https://login.microsoftonline.com/{c.m365_tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": c.m365_client_id,
                "client_secret": c.m365_client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }, timeout=10)
        return r.json()["access_token"]

    def _m365_move(self, report: Report, to_junk: bool = True) -> bool:
        try:
            import requests  # type: ignore
            token = self._m365_token()
            mid = report.source.get("message_id")
            if not mid:
                return False
            folder = "junkemail" if to_junk else "deleteditems"
            requests.post(
                f"https://graph.microsoft.com/v1.0/me/messages/{mid}/move",
                headers={"Authorization": f"Bearer {token}"},
                json={"destinationId": folder}, timeout=10)
            return True
        except Exception:
            return False

    def _gmail_trash(self, report: Report) -> bool:
        try:
            from googleapiclient.discovery import build  # type: ignore
        except Exception:
            return False
        try:
            mid = report.source.get("message_id")
            if not mid:
                return False
            service = build("gmail", "v1", credentials=None)
            service.users().messages().trash(userId="me", id=mid).execute()
            return True
        except Exception:
            return False
