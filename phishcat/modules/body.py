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

EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    re.IGNORECASE
)

PHONE_REGEX = re.compile(
    r'\b\+?\d[\d\s\-]{7,14}\d\b'
)

ANCHOR_REGEX = re.compile(
    r'<a [^>]*href=["\'](.*?)["\']',
    re.IGNORECASE
)

IP_REGEX = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

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


def _ip_check(domain: str) -> bool:
    return bool(IP_REGEX.search(domain))


def _is_shortener(domain: str) -> bool:
    return domain in SHORTENER_DOMAINS


# -------------------------
# Main analysis
# -------------------------

def main(body) -> dict:
    findings = []
    urls_found = set()
    anchors_found = set()
    emails_found = set()
    phones_found = set()

    try:
        # ---- normalize input (dict or string) ----
        if isinstance(body, dict):
            text = body.get("text", "")
            html = body.get("html", "")
            body = (text or "") + "\n" + (html or "")

        if not body or not str(body).strip():
            return {
                "status": "empty",
                "urls": [],
                "anchors": [],
                "emails": [],
                "phones": [],
                "findings": []
            }

        body = str(body)

        # ---- extract URLs ----
        urls = URL_REGEX.findall(body)
        for u in urls:
            urls_found.add(u.strip())

        # ---- extract anchors ----
        anchors = ANCHOR_REGEX.findall(body)
        for a in anchors:
            anchors_found.add(a.strip())

        # ---- extract emails ----
        emails = EMAIL_REGEX.findall(body)
        for e in emails:
            emails_found.add(e.strip())

        # ---- extract phones ----
        phones = PHONE_REGEX.findall(body)
        for p in phones:
            phones_found.add(p.strip())

        # ---- analyze URLs ----
        for url in urls_found.union(anchors_found):
            domain = _normalize_domain(url)
            if not domain:
                continue

            if _ip_check(domain):
                findings.append({
                    "issue": "URL uses IP address instead of domain",
                    "severity": "high",
                    "detail": {"url": url}
                })

            if _is_shortener(domain):
                findings.append({
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": {"url": url, "domain": domain}
                })

        return {
            "status": "done",
            "urls": sorted(urls_found),
            "anchors": sorted(anchors_found),
            "emails": sorted(emails_found),
            "phones": sorted(phones_found),
            "findings": findings
        }

    except Exception as e:
        print("[!] Body module error:", str(e))
        return {
            "status": "error",
            "error": str(e)
        }
