# Dependency check
try:
    import re
    import os
    from urllib.parse import urlparse
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependency: urllib / re / bs4")
    raise


# ---------------- REGEX DEFINITIONS ----------------

URL_REGEX = re.compile(r'(https?://[^\s"<>()]+)', re.IGNORECASE)

ANCHOR_REGEX = re.compile(
    r'<a [^>]*href=["\'](.*?)["\']',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

PHONE_REGEX = re.compile(
    r'\b(\+?\d[\d\s\-]{7,}\d)\b'
)

SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "is.gd", "buff.ly", "ow.ly", "rebrand.ly"
)

IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ---------------- HELPERS ----------------

def _normalize_domain(url: str) -> str | None:
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def _ip_check(url: str) -> bool:
    domain = _normalize_domain(url)
    if not domain:
        return False
    return bool(IP_REGEX.search(domain))


def _load_keywords():
    keywords = []
    path = os.path.join(os.path.dirname(__file__), "keywords.txt")

    if not os.path.isfile(path):
        return keywords

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                keywords.append(word)

    return keywords


# ---------------- MAIN BODY ANALYSIS ----------------

def main(bodies: dict) -> dict:
    """
    Accepts:
        {
          "text/plain": [...],
          "text/html": [...]
        }
    """

    findings = []
    urls_found = set()
    anchors_found = set()
    emails_found = set()
    phones_found = set()
    short_urls = set()
    keyword_hits = set()

    try:
        text_body = ""

        # Prefer plain text
        if bodies.get("text/plain"):
            text_body = "\n".join(bodies["text/plain"])

        # Fallback to HTML
        elif bodies.get("text/html"):
            html = "\n".join(bodies["text/html"])
            soup = BeautifulSoup(html, "lxml")
            text_body = soup.get_text(separator="\n")

        if not text_body or not text_body.strip():
            return {
                "status": "empty",
                "body": "",
                "urls": [],
                "anchors": [],
                "emails": [],
                "phones": [],
                "short_urls": [],
                "keyword_hits": [],
                "findings": []
            }

        # ---------------- URL DETECTION ----------------
        urls = URL_REGEX.findall(text_body)
        for u in urls:
            urls_found.add(u.strip())

        # ---------------- ANCHOR DETECTION ----------------
        anchors = ANCHOR_REGEX.findall(text_body)
        for a in anchors:
            anchors_found.add(a.strip())

        # ---------------- EMAIL DETECTION ----------------
        emails = EMAIL_REGEX.findall(text_body)
        for e in emails:
            emails_found.add(e)

        # ---------------- PHONE DETECTION ----------------
        phones = PHONE_REGEX.findall(text_body)
        for p in phones:
            phones_found.add(p.strip())

        # ---------------- SHORT URL DETECTION ----------------
        for url in urls_found:
            domain = _normalize_domain(url)
            if domain and any(s in domain for s in SHORTENER_DOMAINS):
                short_urls.add(url)
                findings.append({
                    "issue": "Shortened URL detected",
                    "severity": "medium",
                    "detail": url
                })

        # ---------------- IP URL DETECTION ----------------
        for url in urls_found:
            if _ip_check(url):
                findings.append({
                    "issue": "URL uses IP address",
                    "severity": "high",
                    "detail": url
                })

        # ---------------- KEYWORD DETECTION ----------------
        keywords = _load_keywords()
        lower_body = text_body.lower()

        for word in keywords:
            if word in lower_body:
                keyword_hits.add(word)
                findings.append({
                    "issue": "Suspicious keyword",
                    "severity": "medium",
                    "detail": word
                })

        # ---------------- CONSOLE OUTPUT ----------------
        print("[+] Body analysis:")

        if emails_found:
            print("\n[+] Email addresses found:")
            for e in emails_found:
                print(f"  - {e}")

        if phones_found:
            print("\n[+] Phone numbers found:")
            for p in phones_found:
                print(f"  - {p}")

        if urls_found:
            print("\n[+] URLs found:")
            for u in urls_found:
                print(f"  - {u}")

        if findings:
            print("\n[!] Body findings:")
            for f in findings:
                print(f"  - {f['issue']} [{f['severity']}]")

        # ---------------- RETURN STRUCTURE ----------------
        return {
            "status": "done",
            "body": text_body,
            "urls": list(urls_found),
            "anchors": list(anchors_found),
            "emails": list(emails_found),
            "phones": list(phones_found),
            "short_urls": list(short_urls),
            "keyword_hits": list(keyword_hits),
            "findings": findings
        }

    except Exception as e:
        print("[!] Body module error:", str(e))
        return {
            "status": "error",
            "body": "",
            "error": str(e)
        }
