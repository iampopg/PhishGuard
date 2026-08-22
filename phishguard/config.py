from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Config:
    imap_server: str = ""
    imap_username: str = ""
    imap_password: str = ""
    imap_use_ssl: bool = True
    imap_port: int = 993
    imap_mailbox: str = "INBOX"
    imap_unseen_only: bool = True
    imap_mark_read: bool = False
    imap_timeout: int = 30

    vt_api_key: str = ""
    vt_enabled: bool = False

    gsb_api_key: str = ""
    gsb_enabled: bool = False

    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310
    clamav_enabled: bool = False

    sandbox_enabled: bool = False
    sandbox_provider: str = ""
    sandbox_api_key: str = ""
    sandbox_url: str = ""

    monitor_enabled: bool = False
    monitor_interval: int = 60
    monitor_batch: int = 50
    monitor_alert_webhook: str = ""
    monitor_backoff_max: int = 600
    behavioral_enabled: bool = False
    behavioral_baseline_days: int = 30

    org_profile_path: str = ""

    web_host: str = "127.0.0.1"
    web_port: int = 8080
    web_username: str = "admin"
    web_password: str = "admin"
    web_secret_key: str = "change_me"

    report_dir: str = "./reports"

    remediation_enabled: bool = False
    remediation_provider: str = ""
    m365_tenant_id: str = ""
    m365_client_id: str = ""
    m365_client_secret: str = ""
    gmail_service_account_json: str = ""

    export_enabled: bool = False
    export_syslog_addr: str = ""
    export_use_cef: bool = False
    export_webhook_url: str = ""
    export_min_severity: str = "medium"

    threshold_suspicious: int = 30
    threshold_phishing: int = 60
    threshold_malicious: int = 85

    dns_checks_enabled: bool = False

    trusted_domains: List[str] = field(default_factory=list)
    log_level: str = "INFO"

    urlscan_api_key: str = ""
    urlscan_enabled: bool = False

    shodan_api_key: str = ""
    shodan_enabled: bool = False

    otx_api_key: str = ""
    otx_enabled: bool = False

    misp_url: str = ""
    misp_api_key: str = ""
    misp_enabled: bool = False
    misp_verify_ssl: bool = True

    abuseipdb_api_key: str = ""
    abuseipdb_enabled: bool = False

    ai_local_url: str = "http://localhost:11434"
    ai_local_model: str = "llama3.2"
    ai_gemini_key: str = ""
    ai_gemini_model: str = "gemini-2.0-flash"
    ai_claude_key: str = ""
    ai_claude_model: str = "claude-sonnet-4-20250514"
    ai_kilo_key: str = ""
    ai_kilo_model: str = "kilo"

    url_deep_scan_enabled: bool = True
    url_deep_screenshot_enabled: bool = False
    url_deep_max_redirects: int = 5
    url_deep_timeout: int = 15

    evidence_enabled: bool = True
    ti_cache_ttl: int = 3600

    @classmethod
    def load(cls, environ: Optional[dict] = None) -> "Config":
        env = environ if environ is not None else dict(os.environ)
        truthy = {"1", "true", "yes", "on"}

        def flag(key: str, default: bool) -> bool:
            return env.get(key, "").strip().lower() in truthy or (
                default and key not in env
            )

        def integer(key: str, default: int) -> int:
            try:
                return int(env.get(key, default))
            except (TypeError, ValueError):
                return default

        def csv(key: str) -> List[str]:
            return [i.strip().lower() for i in env.get(key, "").split(",") if i.strip()]

        return cls(
            imap_server=env.get("PG_IMAP_SERVER", ""),
            imap_username=env.get("PG_IMAP_USERNAME", ""),
            imap_password=env.get("PG_IMAP_PASSWORD", ""),
            imap_use_ssl=flag("PG_IMAP_USE_SSL", True),
            imap_port=integer("PG_IMAP_PORT", 993),
            imap_mailbox=env.get("PG_IMAP_MAILBOX", "INBOX"),
            imap_unseen_only=flag("PG_IMAP_UNSEEN_ONLY", True),
            imap_mark_read=flag("PG_IMAP_MARK_READ", False),
            imap_timeout=integer("PG_IMAP_TIMEOUT", 30),
            vt_api_key=env.get("PG_VT_API_KEY", ""),
            vt_enabled=flag("PG_VT_ENABLED", False) and bool(env.get("PG_VT_API_KEY")),
            gsb_api_key=env.get("PG_GSB_API_KEY", ""),
            gsb_enabled=flag("PG_GSB_ENABLED", False) and bool(env.get("PG_GSB_API_KEY")),
            clamav_host=env.get("PG_CLAMAV_HOST", "127.0.0.1"),
            clamav_port=integer("PG_CLAMAV_PORT", 3310),
            clamav_enabled=flag("PG_CLAMAV_ENABLED", False),
            sandbox_enabled=flag("PG_SANDBOX_ENABLED", False),
            sandbox_provider=env.get("PG_SANDBOX_PROVIDER", ""),
            sandbox_api_key=env.get("PG_SANDBOX_API_KEY", ""),
            sandbox_url=env.get("PG_SANDBOX_URL", ""),
            monitor_enabled=flag("PG_MONITOR_ENABLED", False),
            monitor_interval=integer("PG_MONITOR_INTERVAL", 60),
            monitor_batch=integer("PG_MONITOR_BATCH", 50),
            monitor_alert_webhook=env.get("PG_MONITOR_ALERT_WEBHOOK", ""),
            monitor_backoff_max=integer("PG_MONITOR_BACKOFF_MAX", 600),
            behavioral_enabled=flag("PG_BEHAVIORAL_ENABLED", False),
            behavioral_baseline_days=integer("PG_BEHAVIORAL_BASELINE_DAYS", 30),
            org_profile_path=env.get("PG_ORG_PROFILE_PATH", ""),
            web_host=env.get("PG_WEB_HOST", "127.0.0.1"),
            web_port=integer("PG_WEB_PORT", 8080),
            web_username=env.get("PG_WEB_USERNAME", "admin"),
            web_password=env.get("PG_WEB_PASSWORD", "admin"),
            web_secret_key=env.get("PG_WEB_SECRET_KEY", "change_me"),
            report_dir=env.get("PG_REPORT_DIR", "./reports"),
            remediation_enabled=flag("PG_REMEDIATION_ENABLED", False),
            remediation_provider=env.get("PG_REMEDIATION_PROVIDER", ""),
            m365_tenant_id=env.get("PG_M365_TENANT_ID", ""),
            m365_client_id=env.get("PG_M365_CLIENT_ID", ""),
            m365_client_secret=env.get("PG_M365_CLIENT_SECRET", ""),
            gmail_service_account_json=env.get("PG_GMAIL_SA_JSON", ""),
            export_enabled=flag("PG_EXPORT_ENABLED", False),
            export_syslog_addr=env.get("PG_EXPORT_SYSLOG_ADDR", ""),
            export_use_cef=flag("PG_EXPORT_CEF", False),
            export_webhook_url=env.get("PG_EXPORT_WEBHOOK_URL", ""),
            export_min_severity=env.get("PG_EXPORT_MIN_SEVERITY", "medium"),
            threshold_suspicious=integer("PG_THRESHOLD_SUSPICIOUS", 30),
            threshold_phishing=integer("PG_THRESHOLD_PHISHING", 60),
            threshold_malicious=integer("PG_THRESHOLD_MALICIOUS", 85),
            dns_checks_enabled=flag("PG_DNS_CHECKS_ENABLED", False),
            trusted_domains=csv("PG_TRUSTED_DOMAINS"),
            log_level=env.get("PG_LOG_LEVEL", "INFO").upper(),
            urlscan_api_key=env.get("PG_URLSCAN_API_KEY", ""),
            urlscan_enabled=flag("PG_URLSCAN_ENABLED", False) and bool(env.get("PG_URLSCAN_API_KEY")),
            shodan_api_key=env.get("PG_SHODAN_API_KEY", ""),
            shodan_enabled=flag("PG_SHODAN_ENABLED", False) and bool(env.get("PG_SHODAN_API_KEY")),
            otx_api_key=env.get("PG_OTX_API_KEY", ""),
            otx_enabled=flag("PG_OTX_ENABLED", False) and bool(env.get("PG_OTX_API_KEY")),
            misp_url=env.get("PG_MISP_URL", ""),
            misp_api_key=env.get("PG_MISP_API_KEY", ""),
            misp_enabled=flag("PG_MISP_ENABLED", False) and bool(env.get("PG_MISP_API_KEY") and env.get("PG_MISP_URL")),
            misp_verify_ssl=flag("PG_MISP_VERIFY_SSL", True),
            abuseipdb_api_key=env.get("PG_ABUSEIPDB_API_KEY", ""),
            abuseipdb_enabled=flag("PG_ABUSEIPDB_ENABLED", False) and bool(env.get("PG_ABUSEIPDB_API_KEY")),
            ai_local_url=env.get("PG_AI_LOCAL_URL", "http://localhost:11434"),
            ai_local_model=env.get("PG_AI_LOCAL_MODEL", "llama3.2"),
            ai_gemini_key=env.get("PG_AI_GEMINI_KEY", ""),
            ai_gemini_model=env.get("PG_AI_GEMINI_MODEL", "gemini-2.0-flash"),
            ai_claude_key=env.get("PG_AI_CLAUDE_KEY", ""),
            ai_claude_model=env.get("PG_AI_CLAUDE_MODEL", "claude-sonnet-4-20250514"),
            ai_kilo_key=env.get("PG_AI_KILO_KEY", ""),
            ai_kilo_model=env.get("PG_AI_KILO_MODEL", "kilo"),
            url_deep_scan_enabled=flag("PG_URL_DEEP_SCAN_ENABLED", True),
            url_deep_screenshot_enabled=flag("PG_URL_DEEP_SCREENSHOT_ENABLED", False),
            url_deep_max_redirects=integer("PG_URL_DEEP_MAX_REDIRECTS", 5),
            url_deep_timeout=integer("PG_URL_DEEP_TIMEOUT", 15),
            evidence_enabled=flag("PG_EVIDENCE_ENABLED", True),
            ti_cache_ttl=integer("PG_TI_CACHE_TTL", 3600),
        )

    @property
    def has_imap_credentials(self) -> bool:
        return bool(self.imap_server and self.imap_username and self.imap_password)
