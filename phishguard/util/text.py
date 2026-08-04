import re
from typing import Dict, List

_HOMOGLYPHS = {
    "0": "o", "1": "l", "1": "i", "5": "s", "8": "b",
    "o": "0", "l": "1", "i": "1", "s": "5", "b": "8",
    "@": "a", "a": "@",
}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def domain_to_ascii(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("xn--"):
        try:
            domain = domain.encode("ascii").decode("idna")
        except Exception:
            pass
    return domain


def normalize_domain(domain: str) -> str:
    dom = domain_to_ascii(domain)
    return dom


def homoglyph_normalize(domain: str) -> str:
    dom = normalize_domain(domain)
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in dom)


def is_lookalike(domain: str, target: str, max_distance: int = 2) -> bool:
    dom = normalize_domain(domain)
    tgt = normalize_domain(target)
    if dom == tgt:
        return False
    if not dom or not tgt:
        return False
    if len(dom) < 4 or len(tgt) < 4:
        return False
    if abs(len(dom) - len(tgt)) > max_distance:
        return False
    if levenshtein(dom, tgt) <= max_distance:
        return True
    if homoglyph_normalize(dom) == tgt or homoglyph_normalize(dom) == homoglyph_normalize(tgt):
        return True
    if tgt in dom and len(dom) - len(tgt) <= 2:
        return True
    return False


_URL_RE = re.compile(
    r"(?P<defang>\b(?:hxxp|hxxps)://|https?://)"
    r"(?P<host>[^\s\"'<>)\]]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    for m in _URL_RE.finditer(text):
        host = m.group("host").rstrip(".,);")
        prefix = "http://" if m.group("defang") else (m.group(0).split("://")[0].lower() + "://")
        if m.group("defang"):
            prefix = "http://" if m.group("defang").startswith("hxxp:") else "https://"
        found.append(prefix + host)
    seen = set()
    out = []
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def registrable_domain(hostname: str) -> str:
    host = hostname.lower().strip()
    if host.startswith("http://") or host.startswith("https://"):
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.split("@")[-1]
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("["):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://")
