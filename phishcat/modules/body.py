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


def _is_shortener(domain: str) -> bool:
    return domain in SHORTENER_DOMAINS


# -------------------------
# Main analysis function
# -------------------------

def main(body: str) -> dict:
    findings = []
    urls_found = set()
    emails_found = set()
    phones_found = set()

    try:
        if not body or not body.strip():
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

        # ---- Emails ----
        emails = EMAIL_REGEX.findall(body)
        for e in emails:
            emails_found.add(e.strip())

        # ---- Phones ----
        phones = PHONE_REGEX.findall(body)
        for p in phones:
            phones_found.add(p.strip())

        # ---- URL analysis ----
        for url in urls_found:
            domain = _normalize_domain(url)
            if not domain:
                continue

            if _is_shortener(domain):
                findings.append({
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": {"url": url, "domain": domain}
                })

        # ---- Console output (debug style) ----
        print("[+] Full body (readable):\n")
        print(body[:1000] + ("\n...[truncated]" if len(body) > 1000 else ""))

        if urls_found:
            print("\n[+] URLs found:")
            for u in urls_found:
                print(f"  - {u}")

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
                print(f"  - {f['detail']['url']} ({f['issue']})")
        else:
            print("\n[+] No suspicious URLs detected")

        return {
            "status": "done",
            "body": body,
            "urls": list(urls_found),
            "emails": list(emails_found),
            "phones": list(phones_found),
            "findings": findings
        }

    except Exception as e:
        print("[!] Body module error:", str(e))
        return {
            "status": "error",
            "body": body,
            "error": str(e)
        }
