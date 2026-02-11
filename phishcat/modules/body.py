# Dependency check
try:
    import re
    from urllib.parse import urlparse
except ImportError:
    print("[!] Missing dependency: urllib / re")
    raise

# Homoglyph mapping
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

# URL regex
URL_REGEX = re.compile(r'(https?://[^\s"<>()]+)', re.IGNORECASE)

# Anchor tag href regex
ANCHOR_REGEX = re.compile(r'<a [^>]*href=["\'](.*?)["\']', re.IGNORECASE)
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

# IP detection regex
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

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


def _homoglyph_check(domain: str) -> list:
    hits = []

    # flag any non-ASCII character
    for ch in domain:
        if ord(ch) > 127:
            hits.append(ch)

    # check explicit homoglyphs
    for _, lookalikes in HOMOGLYPHS.items():
        for g in lookalikes:
            if g in domain:
                hits.append(g)

    return list(set(hits))


def _ip_check(url: str) -> bool:
    domain = _normalize_domain(url)
    if not domain:
        return False
    return bool(IP_REGEX.search(domain))

def _is_shortener(domain: str) -> bool:
    return domain in SHORTENER_DOMAINS

def main(body) -> dict:
    """
    Body analysis with:
    - full body preserved
    - all URLs
    - all anchor tag hrefs
    - homoglyph detection
    - IP-based URL detection
    """

    # ---- normalize input (fix for dict body structure) ----
    if isinstance(body, dict):
        text = body.get("text", "")
        html = body.get("html", "")
        body = (text or "") + "\n" + (html or "")
# -------------------------
# Main analysis function
# -------------------------

def main(body: str) -> dict:
    findings = []
    urls_found = set()
    anchors_found = set()
    emails_found = set()
    phones_found = set()

    try:
        if not body or not body.strip():
            return {"status": "empty", "body": body, "urls": [], "anchors": [], "findings": []}

        # ---- extract URLs ----
            return {
                "status": "empty",
                "body": body,
                "urls": [],
                "emails": [],
                "phones": [],
                "findings": []
            }

        # ---- URLs ----
        urls = URL_REGEX.findall(body)
        for u in urls:
            urls_found.add(u.strip())

        # ---- extract anchor hrefs ----
        anchors = ANCHOR_REGEX.findall(body)
        for a in anchors:
            anchors_found.add(a.strip())
        # ---- Emails ----
        emails = EMAIL_REGEX.findall(body)
        for e in emails:
            emails_found.add(e.strip())

        # ---- Phones ----
        phones = PHONE_REGEX.findall(body)
        for p in phones:
            phones_found.add(p.strip())

        # ---- analyze URLs and anchors ----
        for url in urls_found.union(anchors_found):
        # ---- URL analysis ----
        for url in urls_found:
            domain = _normalize_domain(url)
            if not domain:
                continue

            # homoglyph / lookalike
            homoglyph_hits = _homoglyph_check(domain)
            if homoglyph_hits:
                findings.append({
                    "issue": "Domain contains suspicious lookalike characters",
                    "severity": "high",
                    "detail": {"url": url, "domain": domain, "matched": homoglyph_hits}
                })

            # IP-based URLs
            if _ip_check(url):
            if _is_shortener(domain):
                findings.append({
                    "issue": "URL uses IP address instead of domain",
                    "severity": "high",
                    "detail": {"url": url}
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": {"url": url, "domain": domain}
                })

        # ---- human-readable output ----
        # ---- Console output (debug style) ----
        print("[+] Full body (readable):\n")
        print(body[:1000] + ("\n...[truncated]" if len(body) > 1000 else ""))

        if urls_found:
            print("\n[+] URLs found in body:")
            print("\n[+] URLs found:")
            for u in urls_found:
                print(f"  - {u}")

        if anchors_found:
            print("\n[+] Anchor hrefs found in body:")
            for a in anchors_found:
                print(f"  - {a}")
        if emails_found:
            print("\n[+] Email addresses found:")
            for e in emails_found:
                print(f"  - {e}")

        if phones_found:
            print("\n[+] Phone numbers found:")
            for p in phones_found:
                print(f"  - {p}")

        if findings:
            print("\n[!] Suspicious findings:")
            for f in findings:
                if "domain" in f["detail"]:
                    print(f"  - {f['detail']['domain']} ({f['issue']})")
                else:
                    print(f"  - {f['detail']['url']} ({f['issue']})")
                print(f"  - {f['detail']['url']} ({f['issue']})")
        else:
            print("\n[+] No homoglyphs or IP-based URLs detected")
            print("\n[+] No suspicious URLs detected")

        return {
            "status": "done",
            "body": body,
            "urls": list(urls_found),
            "anchors": list(anchors_found),
            "emails": list(emails_found),
            "phones": list(phones_found),
            "findings": findings
        }

    except Exception as e:
        print("[!] Body module error:", str(e))
        return {"status": "error", "body": body, "error": str(e)}
        return {
            "status": "error",
            "body": body,
            "error": str(e)
        }
