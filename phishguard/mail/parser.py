from __future__ import annotations

import base64
import binascii
import email
import hashlib
import re
from email.message import Message
from typing import List, Optional

from phishguard.models import Attachment, AuthResult, ParsedEmail
from phishguard.util.text import extract_urls, registrable_domain

_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)', re.IGNORECASE)


def _decode_payload(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        try:
            payload = base64.b64decode(raw)
        except (binascii.Error, ValueError):
            payload = raw.encode("utf-8", "replace") if isinstance(raw, str) else b""
    return payload


def _parse_addr(header_value: Optional[str]):
    if not header_value:
        return "", ""
    name, addr = email.utils.parseaddr(header_value)
    return name, addr


def _auth_results_dict(msg: Message) -> dict:
    res = msg.get("Authentication-Results", "")
    out = {}
    for kind, val in re.findall(r"(spf|dkim|dmarc)=(\w+)", res, re.IGNORECASE):
        out[kind.lower()] = val.lower()
    return out


def _auth_from_headers(msg: Message, auth_results: dict, sender_domain: str) -> AuthResult:
    spf = auth_results.get("spf", "unknown")
    dkim = auth_results.get("dkim", "unknown")
    dmarc = auth_results.get("dmarc", "unknown")
    env = msg.get("Return-Path")
    env_domain = registrable_domain(env) if env else None
    aligned = bool(env_domain and env_domain == sender_domain)
    return AuthResult(
        spf=spf, dkim=dkim, dmarc=dmarc,
        aligned=aligned, envelope_domain=env_domain,
    )


def _extract_html_urls(html: str) -> List[str]:
    urls = extract_urls(html)
    for m in _HREF_RE.finditer(html):
        u = m.group(1).strip()
        if u.lower().startswith(("http://", "https://")):
            urls.append(u)
    return urls


def parse_message(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw)

    from_name, from_addr = _parse_addr(msg.get("From"))
    to_name, to_addr = _parse_addr(msg.get("To"))
    sender_domain = registrable_domain(from_addr)
    auth_results = _auth_results_dict(msg)
    receiver_domain = registrable_domain(to_addr)

    body_text = ""
    body_html = ""
    attachments: List[Attachment] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        fname = part.get_filename()
        if fname or "attachment" in disp:
            data = _decode_payload(part)
            attachments.append(Attachment(
                filename=fname or "unnamed",
                content_type=ctype or "application/octet-stream",
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                md5=hashlib.md5(data).hexdigest(),
                payload=data,
            ))
        elif ctype == "text/plain" and not body_text:
            body_text = _decode_payload(part).decode("utf-8", "replace")
        elif ctype == "text/html" and not body_html:
            body_html = _decode_payload(part).decode("utf-8", "replace")

    urls = list(dict.fromkeys(extract_urls(body_text) + _extract_html_urls(body_html)))

    return ParsedEmail(
        message_id=msg.get("Message-ID"),
        subject=msg.get("Subject"),
        from_header=msg.get("From"),
        to_header=msg.get("To"),
        date_header=msg.get("Date"),
        sender_name=from_name,
        sender_email=from_addr,
        sender_domain=sender_domain,
        receiver_email=to_addr,
        receiver_domain=receiver_domain,
        envelope_from=(msg.get("Return-Path") or "").strip("<> ").lower() or None,
        reply_to=_parse_addr(msg.get("Reply-To"))[1] or None,
        return_path=_parse_addr(msg.get("Return-Path"))[1] or None,
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
        auth=_auth_from_headers(msg, auth_results, sender_domain),
        authentication_results=auth_results,
        raw_headers={k: v for k, v in msg.items()},
    )
