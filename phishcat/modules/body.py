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

EMAIL_REGEX = re.compile(
    r'\b\S+@\S+\b',
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
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at"
}

MEDIA_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".pdf", ".zip", ".rar", ".7z"
)

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


def _is_media(url: str) -> bool:
    url = url.lower()
    return any(url.endswith(ext) for ext in MEDIA_EXTENSIONS)


# -------------------------
# Main analysis
# -------------------------

def main(body_input) -> dict:
    findings = []
    urls_found = set()
    anchors_found = set()
    emails_found = set()
    phones_found = set()

    # Normalize body
    if isinstance(body_input, dict):
        text = body_input.get("text", "")
        html = body_input.get("html", "")
        body = (text or "") + "\n" + (html or "")
    else:
        body = body_input or ""

    try:
        if not body.strip():
            return {
                "status": "empty",
                "content": "",
                "urls": [],
                "media_urls": [],
                "emails": [],
                "phones": [],
                "findings": []
            }

        # Extract URLs
        for u in URL_REGEX.findall(body):
            urls_found.add(u.strip())

        for a in ANCHOR_REGEX.findall(body):
            anchors_found.add(a.strip())

        all_urls = urls_found.union(anchors_found)

        # Extract emails
        for e in EMAIL_REGEX.findall(body):
            emails_found.add(e.strip())

        # Extract phones
        for p in PHONE_REGEX.findall(body):
            phones_found.add(p.strip())

        # Analyze URLs
        for url in all_urls:
            domain = _normalize_domain(url)
            if not domain:
                continue

            if _contains_unicode(domain):
                findings.append({
                    "issue": "Unicode characters in URL domain",
                    "severity": "medium",
                    "detail": url
                })

            if _ip_check(url):
                findings.append({
                    "issue": "URL uses IP address",
                    "severity": "high",
                    "detail": url
                })

            if _is_shortener(domain):
                findings.append({
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": url
                })

        # Unicode in emails
        for e in emails_found:
            if _contains_unicode(e):
                findings.append({
                    "issue": "Unicode characters in email address",
                    "severity": "medium",
                    "detail": e
                })

        # Separate media URLs
        media_urls = set()
        normal_urls = set()

        for u in all_urls:
            if _is_media(u):
                media_urls.add(u)
            else:
                normal_urls.add(u)

        return {
            "status": "done",
            "content": body.strip(),
            "urls": sorted(normal_urls),
            "media_urls": sorted(media_urls),
            "emails": sorted(emails_found),
            "phones": sorted(phones_found),
            "findings": findings
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
