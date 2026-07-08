try:
    import re
    import os
    from email.utils import parseaddr
except ImportError:
    print("[!] Missing dependency: email / re")
    raise


# Homoglyph / lookalike chars (Latin → Unicode lookalikes)
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
# Helper functions
# -------------------------

def _domain(addr: str | None) -> str | None:
    if not addr:
        return None
    _, email_addr = parseaddr(addr)
    if "@" not in email_addr:
        return None
    return email_addr.split("@")[-1].lower()


def _related(domain: str, base: str) -> bool:
    return domain == base or domain.endswith("." + base)


def _extract_auth_result(headers: dict, key: str) -> str | None:
    h = headers.get("Authentication-Results", "")
    m = re.search(rf"{key}=([a-zA-Z]+)", h)
    return m.group(1).lower() if m else None


def _extract_auth_domain(headers: dict, key: str) -> str | None:
    h = headers.get("Authentication-Results", "")
    m = re.search(rf"{key}=[^;]+?@([^;\s]+)", h)
    return m.group(1).lower() if m else None


def _homoglyph_check(value: str) -> list:
    hits = []

    # flag any non-ASCII immediately
    for ch in value:
        if ord(ch) > 127:
            hits.append(ch)

    # explicit homoglyph matches
    for _, lookalikes in HOMOGLYPHS.items():
        for g in lookalikes:
            if g in value:
                hits.append(g)

    return list(set(hits))


def _load_local_keywords() -> list:
    """Finds and loads custom keywords from a local file in the same directory."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    possible_names = ["keywords.txt", "keyword_list.txt", "keywords.cfg"]
    for name in possible_names:
        file_path = os.path.join(current_dir, name)
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
    return []


def _detect_script_words(text: str) -> list:
    """Flags any word containing at least one character from Cyrillic or Greek scripts."""
    flagged_words = set()
    words = re.findall(r'\b\w+\b', text)
    
    cyrillic_pattern = re.compile(r'[\u0400-\u04FF\u0500-\u052F]')
    greek_pattern = re.compile(r'[\u0370-\u03FF\u1F00-\u1FFF]')

    for word in words:
        if cyrillic_pattern.search(word) or greek_pattern.search(word):
            flagged_words.add(word)
            
    return list(flagged_words)


# -------------------------
# Main analysis function
# -------------------------

def main(headers: dict) -> dict:
    findings = []

    try:
        from_raw = headers.get("From")
        from_domain = _domain(from_raw)

        if not from_domain:
            findings.append({
                "issue": "Missing or invalid From header",
                "severity": "high",
                "detail": ""
            })
            return {"status": "weak", "findings": findings}

        identities = {
            "From": from_raw,
            "Return-Path": headers.get("Return-Path"),
            "Reply-To": headers.get("Reply-To"),
            "Sender": headers.get("Sender"),
            "Message-ID": headers.get("Message-ID"),
        }

        # Include subject if present for comprehensive text scanning
        subject = headers.get("Subject", "")

        domains = {
            k: _domain(v) if k != "Message-ID" else (
                v.split("@")[-1].strip(">") if v and "@" in v else None
            )
            for k, v in identities.items()
        }

        # ---- homoglyph / unicode detection ----
        for src, val in identities.items():
            if not val:
                continue
            hits = _homoglyph_check(val)
            if hits:
                findings.append({
                    "issue": f"Lookalike / Unicode characters in {src}",
                    "severity": "high",
                    "detail": {
                        "value": val,
                        "matched": hits
                    }
                })

        # ---- NEW FEATURE 1: Keyword matching within headers ----
        custom_keywords = _load_local_keywords()
        for src, val in {**identities, "Subject": subject}.items():
            if not val:
                continue
            matched_keywords = []
            for kw in custom_keywords:
                if re.search(r'\b' + re.escape(kw) + r'\b', val, re.IGNORECASE):
                    matched_keywords.append(kw)
            
            if matched_keywords:
                findings.append({
                    "issue": f"Custom keyword list match in {src}",
                    "severity": "medium",
                    "detail": {"matched_keywords": matched_keywords, "header_value": val}
                })

        # ---- NEW FEATURE 2: Target Script Character Detection ----
        for src, val in {**identities, "Subject": subject}.items():
            if not val:
                continue
            script_words = _detect_script_words(val)
            for word in script_words:
                findings.append({
                    "issue": f"Targeted script character detected in {src} word",
                    "severity": "medium",
                    "detail": {"word": word, "header_value": val}
                })

        # ---- display name spoofing ----
        display_name, _ = parseaddr(from_raw)
        if display_name and from_domain not in display_name.lower():
            findings.append({
                "issue": "Display-name spoofing suspected",
                "severity": "medium",
                "detail": f"Display='{display_name}', From domain={from_domain}"
            })

        # ---- domain alignment ----
        for src, dom in domains.items():
            if dom and not _related(dom, from_domain):
                findings.append({
                    "issue": f"{src} domain mismatch",
                    "severity": "high",
                    "detail": f"{dom} != {from_domain}"
                })

        # ---- authentication results ----
        spf = _extract_auth_result(headers, "spf")
        dkim = _extract_auth_result(headers, "dkim")
        dmarc = _extract_auth_result(headers, "dmarc")
        arc = _extract_auth_result(headers, "arc")

        spf_dom = _extract_auth_domain(headers, "spf")
        dkim_dom = _extract_auth_domain(headers, "dkim")

        auth = {"SPF": spf, "DKIM": dkim, "DMARC": dmarc, "ARC": arc}

        if spf == "pass" and spf_dom and not _related(spf_dom, from_domain):
            findings.append({
                "issue": "SPF passed but misaligned",
                "severity": "high",
                "detail": f"{spf_dom} != {from_domain}"
            })

        if dkim == "pass" and dkim_dom and not _related(dkim_dom, from_domain):
            findings.append({
                "issue": "DKIM passed but misaligned",
                "severity": "high",
                "detail": f"{dkim_dom} != {from_domain}"
            })

        if dmarc and dmarc != "pass":
            findings.append({
                "issue": f"DMARC {dmarc}",
                "severity": "medium",
                "detail": ""
            })

        # ---- output ----
        if findings:
            print("[!] Header anomalies detected:")
            for f in findings:
                print(f"   - {f['issue']} [{f['severity']}]")
        else:
            print("[+] Header analysis clean")

        return {
            "status": "done",
            "from_domain": from_domain,
            "identities": identities,
            "domains": domains,
            "auth": auth,
            "findings": findings
        }

    except Exception as e:
        print("[!] Header module error:", str(e))
        return {"status": "error", "error": str(e)}
