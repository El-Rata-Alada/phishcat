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

# IP detection regex
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _normalize_domain(url: str) -> str | None:
    try:
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

    findings = []
    urls_found = set()
    anchors_found = set()

    try:
        if not body or not body.strip():
            return {"status": "empty", "body": body, "urls": [], "anchors": [], "findings": []}

        # ---- extract URLs ----
        urls = URL_REGEX.findall(body)
        for u in urls:
            urls_found.add(u.strip())

        # ---- extract anchor hrefs ----
        anchors = ANCHOR_REGEX.findall(body)
        for a in anchors:
            anchors_found.add(a.strip())

        # ---- analyze URLs and anchors ----
        for url in urls_found.union(anchors_found):
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
                findings.append({
                    "issue": "URL uses IP address instead of domain",
                    "severity": "high",
                    "detail": {"url": url}
                })

        # ---- human-readable output ----
        print("[+] Full body (readable):\n")
        print(body[:1000] + ("\n...[truncated]" if len(body) > 1000 else ""))

        if urls_found:
            print("\n[+] URLs found in body:")
            for u in urls_found:
                print(f"  - {u}")

        if anchors_found:
            print("\n[+] Anchor hrefs found in body:")
            for a in anchors_found:
                print(f"  - {a}")

        if findings:
            print("\n[!] Suspicious findings:")
            for f in findings:
                if "domain" in f["detail"]:
                    print(f"  - {f['detail']['domain']} ({f['issue']})")
                else:
                    print(f"  - {f['detail']['url']} ({f['issue']})")
        else:
            print("\n[+] No homoglyphs or IP-based URLs detected")

        return {
            "status": "done",
            "body": body,
            "urls": list(urls_found),
            "anchors": list(anchors_found),
            "findings": findings
        }

    except Exception as e:
        print("[!] Body module error:", str(e))
        return {"status": "error", "body": body, "error": str(e)}
