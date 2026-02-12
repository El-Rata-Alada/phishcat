# Dependency check
try:
    import re
    from urllib.parse import urlparse
except ImportError:
    print("[!] Missing dependency: urllib / re")
    raise

# -------------------------
# Homoglyph mapping
# -------------------------
HOMOGLYPHS = {
    "a": ["а", "ɑ"],
    "c": ["с"],
    "e": ["е"],
    "i": ["і", "1"],
    "o": ["о", "0"],
    "p": ["р"],
    "s": ["ѕ", "$"],
    "y": ["у"],
    "l": ["ⅼ", "1", "!"],
}

# -------------------------
# Regex patterns
# -------------------------

URL_REGEX = re.compile(
    r'\b(?:https?://|www\.)[^\s"<>()]+',
    re.IGNORECASE
)

ANCHOR_REGEX = re.compile(
    r'<a [^>]*href=["\'](.*?)["\']',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    re.IGNORECASE
)

PHONE_REGEX = re.compile(
    r'\b\+?\d[\d\s\-]{7,14}\d\b'
)

IP_REGEX = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

# Shortened URL domains
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at"
}


# -------------------------
# Helper functions
# -------------------------

def _normalize_domain(url: str) -> str | None:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def _homoglyph_check(value: str) -> list:
    hits = []

    for ch in value:
        if ord(ch) > 127:
            hits.append(ch)

    for _, lookalikes in HOMOGLYPHS.items():
        for g in lookalikes:
            if g in value:
                hits.append(g)

    return list(set(hits))


def _ip_check(url: str) -> bool:
    domain = _normalize_domain(url)
    if not domain:
        return False
    return bool(IP_REGEX.search(domain))


def _is_shortener(domain: str) -> bool:
    return domain in SHORTENER_DOMAINS


# -------------------------
# Main analysis function
# -------------------------

def main(body_input) -> dict:
    findings = []
    urls_found = set()
    anchors_found = set()
    emails_found = set()
    phones_found = set()

    # ---- normalize input ----
    if isinstance(body_input, dict):
        text = body_input.get("text", "")
        html = body_input.get("html", "")
        body = (text or "") + "\n" + (html or "")
    else:
        body = body_input or ""

    try:
        if not body or not body.strip():
            return {
                "status": "empty",
                "urls": [],
                "emails": [],
                "phones": [],
                "findings": []
            }

        # ---- extract URLs ----
        for u in URL_REGEX.findall(body):
            urls_found.add(u.strip())

        # ---- extract anchor hrefs ----
        for a in ANCHOR_REGEX.findall(body):
            anchors_found.add(a.strip())

        # ---- extract emails ----
        for e in EMAIL_REGEX.findall(body):
            emails_found.add(e.strip())

        # ---- extract phones ----
        for p in PHONE_REGEX.findall(body):
            phones_found.add(p.strip())

        # ---- analyze URLs ----
        for url in urls_found.union(anchors_found):
            domain = _normalize_domain(url)
            if not domain:
                continue

            # homoglyph / unicode
            homoglyph_hits = _homoglyph_check(domain)
            if homoglyph_hits:
                findings.append({
                    "issue": "Domain contains suspicious lookalike or Unicode characters",
                    "severity": "high",
                    "detail": {
                        "url": url,
                        "matched": homoglyph_hits
                    }
                })

            # IP-based URL
            if _ip_check(url):
                findings.append({
                    "issue": "URL uses IP address instead of domain",
                    "severity": "high",
                    "detail": {"url": url}
                })

            # shortened URL
            if _is_shortener(domain):
                findings.append({
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": {"url": url}
                })

        # ---- detect homoglyph/unicode in words ----
        words = re.findall(r'\b\S+\b', body)
        for w in words:
            hits = _homoglyph_check(w)
            if hits:
                findings.append({
                    "issue": "Suspicious characters in word",
                    "severity": "medium",
                    "detail": {
                        "value": w,
                        "matched": hits
                    }
                })

        return {
            "status": "done",
            "urls": list(urls_found),
            "anchors": list(anchors_found),
            "emails": list(emails_found),
            "phones": list(phones_found),
            "findings": findings
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
