# Dependency check
try:
    import re
    import os
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
# Load keyword list
# -------------------------

def _load_keywords():
    keywords = []
    try:
        base_dir = os.path.dirname(__file__)
        path = os.path.join(base_dir, "keywords.txt")

        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    kw = line.strip().lower()
                    if kw:
                        keywords.append(kw)
    except Exception:
        pass

    return keywords


KEYWORDS = _load_keywords()


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


def _extract_text(body_input):
    """
    Accepts either:
    - string body
    - loader body dict
    Returns a single text string.
    """
    if isinstance(body_input, str):
        return body_input

    if isinstance(body_input, dict):
        # Prefer plain text
        if body_input.get("text/plain"):
            return "\n".join(body_input["text/plain"])
        elif body_input.get("text/html"):
            return "\n".join(body_input["text/html"])

    return ""


# -------------------------
# Main analysis
# -------------------------

def main(body_input) -> dict:
    findings = []
    urls_found = set()
    emails_found = set()
    phones_found = set()
    keyword_hits = set()

    try:
        body = _extract_text(body_input)

        if not body or not body.strip():
            return {
                "status": "empty",
                "body": body,
                "urls": [],
                "emails": [],
                "phones": [],
                "keywords": [],
                "findings": []
            }

        body_lower = body.lower()

        # ---- URLs ----
        for u in URL_REGEX.findall(body):
            urls_found.add(u.strip())

        # ---- Emails ----
        for e in EMAIL_REGEX.findall(body):
            emails_found.add(e.strip())

        # ---- Phones ----
        for p in PHONE_REGEX.findall(body):
            phones_found.add(p.strip())

        # ---- Keyword matching ----
        for kw in KEYWORDS:
            if kw in body_lower:
                keyword_hits.add(kw)
                findings.append({
                    "issue": f"Keyword match: '{kw}'",
                    "severity": "medium",
                    "detail": {}
                })

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

        # ---- Console output ----
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

        if keyword_hits:
            print("\n[!] Keyword matches:")
            for k in keyword_hits:
                print(f"  - {k}")

        if findings:
            print("\n[!] Suspicious findings detected")
        else:
            print("\n[+] No suspicious indicators detected")

        return {
            "status": "done",
            "body": body,
            "urls": list(urls_found),
            "emails": list(emails_found),
            "phones": list(phones_found),
            "keywords": list(keyword_hits),
            "findings": findings
        }

    except Exception as e:
        print("[!] Body module error:", str(e))
        return {
            "status": "error",
            "body": "",
            "error": str(e)
        }
