# Dependency check
try:
    import re
    from urllib.parse import urlparse
except ImportError:
    print("[!] Missing dependency: urllib / re")
    raise

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

# strict email
EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
    re.IGNORECASE
)

# loose phone detection
PHONE_CANDIDATE_REGEX = re.compile(
    r'[\+\(]?\d[\d\-\s\(\)]{5,}\d'
)

IP_REGEX = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at"
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


def _ip_check(url: str) -> bool:
    domain = _normalize_domain(url)
    if not domain:
        return False
    return bool(IP_REGEX.search(domain))


def _is_shortener(domain: str) -> bool:
    return domain in SHORTENER_DOMAINS


def _contains_unicode(value: str) -> bool:
    for ch in value:
        if ord(ch) > 127:
            return True
    return False


def _normalize_phone(candidate: str) -> str | None:
    digits = re.sub(r'\D', '', candidate)
    if 7 <= len(digits) <= 15:
        return digits
    return None


# -------------------------
# Main analysis
# -------------------------

def main(body_input) -> dict:
    findings = []
    urls_found = set()
    anchors_found = set()
    emails_found = set()
    phones_found = set()

    # ---- normalize input ----
    if isinstance(body_input, dict):
        text_parts = body_input.get("text/plain", [])
        html_parts = body_input.get("text/html", [])

        text = "\n".join(text_parts) if text_parts else ""
        html = "\n".join(html_parts) if html_parts else ""

        body = text + "\n" + html
    else:
        body = body_input or ""

    try:
        if not body.strip():
            return {
                "status": "empty",
                "urls": [],
                "emails": [],
                "phones": [],
                "findings": []
            }

        # ---- URLs ----
        for u in URL_REGEX.findall(body):
            urls_found.add(u.strip())

        # ---- anchor hrefs ----
        for a in ANCHOR_REGEX.findall(body):
            anchors_found.add(a.strip())

        # ---- strict emails ----
        for e in EMAIL_REGEX.findall(body):
            emails_found.add(e.strip())

        # ---- fallback: any word with @ ----
        tokens = re.findall(r'\b\S+\b', body)
        for t in tokens:
            if "@" in t:
                emails_found.add(t.strip())

        # ---- phone detection ----
        for candidate in PHONE_CANDIDATE_REGEX.findall(body):
            normalized = _normalize_phone(candidate)
            if normalized:
                phones_found.add(normalized)

        # ---- analyze URLs ----
        for url in urls_found.union(anchors_found):
            domain = _normalize_domain(url)
            if not domain:
                continue

            if _contains_unicode(domain):
                findings.append({
                    "issue": "Unicode characters in URL domain",
                    "severity": "medium",
                    "detail": {"url": url}
                })

            if _ip_check(url):
                findings.append({
                    "issue": "URL uses IP address instead of domain",
                    "severity": "high",
                    "detail": {"url": url}
                })

            if _is_shortener(domain):
                findings.append({
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": {"url": url}
                })

        # ---- unicode in emails ----
        for e in emails_found:
            if _contains_unicode(e):
                findings.append({
                    "issue": "Unicode characters in email address",
                    "severity": "medium",
                    "detail": {"value": e}
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
