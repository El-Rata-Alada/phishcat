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

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
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


def _load_local_keywords() -> list:
    """Finds and loads custom keywords from a local file in the same directory."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Looks for variations of keyword lists in the script's folder
    possible_names = ["keywords.txt", "keyword_list.txt", "keywords.cfg"]
    for name in possible_names:
        file_path = os.path.join(current_dir, name)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    # Filter out comments or empty lines
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
    return []


def _detect_script_words(text: str) -> list:
    """
    Flags any word containing at least one character from Cyrillic or Greek scripts.
    Note: Latin is defined here, but ignored by default so standard English words 
    don't overwhelm your findings list.
    """
    flagged_words = set()
    
    # Split text into individual alphanumeric words
    words = re.findall(r'\b\w+\b', text)
    
    # Character ranges for the target scripts
    cyrillic_pattern = re.compile(r'[\u0400-\u04FF\u0500-\u052F]')
    greek_pattern = re.compile(r'[\u0370-\u03FF\u1F00-\u1FFF]')
    latin_pattern = re.compile(r'[a-zA-Z]')

    for word in words:
        if cyrillic_pattern.search(word):
            flagged_words.add(word)
        elif greek_pattern.search(word):
            flagged_words.add(word)
        elif latin_pattern.search(word):
            # If your email is written in a non-Western script (e.g. Arabic/Hebrew) 
            # and you want to flag any English/Latin words, uncomment the line below:
            # flagged_words.add(word)
            pass
            
    return list(flagged_words)


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
        if not body.strip():
            return {
                "status": "empty",
                "urls": [],
                "emails": [],
                "phones": [],
                "findings": []
            }

        # ---- extract basic features ----
        for u in URL_REGEX.findall(body):
            urls_found.add(u.strip())

        for a in ANCHOR_REGEX.findall(body):
            anchors_found.add(a.strip())

        for e in EMAIL_REGEX.findall(body):
            emails_found.add(e.strip())

        for p in PHONE_REGEX.findall(body):
            phones_found.add(p.strip())

        # ---- Feature 1: Local Keyword Scan ----
        custom_keywords = _load_local_keywords()
        matched_keywords = []
        for kw in custom_keywords:
            if re.search(r'\b' + re.escape(kw) + r'\b', body, re.IGNORECASE):
                matched_keywords.append(kw)
        
        if matched_keywords:
            findings.append({
                "issue": "Custom keyword list match",
                "severity": "medium",
                "detail": {"matched_keywords": matched_keywords}
            })

        # ---- Feature 2: Target Script Character Detection ----
        script_words = _detect_script_words(body)
        for word in script_words:
            findings.append({
                "issue": "Targeted script character detected in word",
                "severity": "medium",
                "detail": {"word": word}
            })

        # ---- suspicious @-tokens ----
        tokens = re.findall(r'\b\S+@\S+\b', body)
        for t in tokens:
            cleaned = t.strip('.,;:()[]<>\"\'')
            
            if cleaned in emails_found or cleaned.startswith("http") or "/" in cleaned or re.search(r'@\d+x', cleaned):
                continue

            findings.append({
                "issue": "Suspicious @-token in body",
                "severity": "low",
                "detail": {"value": cleaned}
            })

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

        # ---- unicode in email addresses ----
        for e in emails_found:
            if _contains_unicode(e):
                findings.append({
                    "issue": "Unicode characters in email address",
                    "severity": "medium",
                    "detail": {"value": e}
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
        return {
            "status": "error",
            "error": str(e)
        }
