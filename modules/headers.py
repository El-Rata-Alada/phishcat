
# Dependency check
try:
    import re
    from email.utils import parseaddr
except ImportError:
    print("[!] Missing stdlib dependency: email / re")
    raise


def _domain(addr: str | None) -> str | None:
    if not addr:
        return None
    _, email_addr = parseaddr(addr)
    if "@" not in email_addr:
        return None
    return email_addr.split("@")[-1].lower()


def _related(domain: str, base: str) -> bool:
    # same domain or subdomain
    return domain == base or domain.endswith("." + base)


def _extract_auth_result(headers: dict, key: str) -> str | None:
    """Extract result (pass/fail/none) for SPF/DKIM/DMARC/ARC"""
    h = headers.get("Authentication-Results", "")
    m = re.search(rf"{key}=([a-zA-Z]+)", h)
    return m.group(1).lower() if m else None


def _extract_auth_domain(headers: dict, key: str) -> str | None:
    """Extract signing domain from Authentication-Results for SPF/DKIM"""
    h = headers.get("Authentication-Results", "")
    m = re.search(rf"{key}=[^;]+?header\.i=@([^;\s]+)", h)
    return m.group(1).lower() if m else None


def main(headers: dict) -> dict:
    """
    Max phishing-aware header analysis.

    Returns dict:
    {
        "status": "done",
        "from_domain": str,
        "findings": list of dict(issue, severity, detail),
        "auth": dict(SPF, DKIM, DMARC, ARC)
    }
    """
    findings = []

    try:
        # ----- extract domains -----
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
            "Return-Path": _domain(headers.get("Return-Path")),
            "Reply-To": _domain(headers.get("Reply-To")),
            "Sender": _domain(headers.get("Sender")),
        }

        # ----- display-name spoofing -----
        display_name, _ = parseaddr(from_raw)
        if display_name and from_domain not in display_name.lower():
            findings.append({
                "issue": "Display-name might be spoofed",
                "severity": "medium",
                "detail": f"Display='{display_name}', From domain={from_domain}"
            })

        # ----- multiple From headers -----
        if isinstance(headers.get("From"), list):
            findings.append({
                "issue": "Multiple From headers detected",
                "severity": "high",
                "detail": str(headers.get("From"))
            })

        # ----- authentication results -----
        spf = _extract_auth_result(headers, "spf")
        dkim = _extract_auth_result(headers, "dkim")
        dmarc = _extract_auth_result(headers, "dmarc")
        arc = _extract_auth_result(headers, "arc")

        spf_dom = _extract_auth_domain(headers, "spf")
        dkim_dom = _extract_auth_domain(headers, "dkim")

        auth = {"SPF": spf, "DKIM": dkim, "DMARC": dmarc, "ARC": arc}

        # ----- alignment checks -----
        for src, dom in identities.items():
            if dom and not _related(dom, from_domain):
                findings.append({
                    "issue": f"{src} domain mismatch",
                    "severity": "high",
                    "detail": f"{dom} does not match From domain {from_domain}"
                })

        if spf == "pass" and spf_dom and not _related(spf_dom, from_domain):
            findings.append({
                "issue": "SPF passed but misaligned",
                "severity": "high",
                "detail": f"SPF domain={spf_dom} != From domain={from_domain}"
            })

        if dkim == "pass" and dkim_dom and not _related(dkim_dom, from_domain):
            findings.append({
                "issue": "DKIM passed but misaligned",
                "severity": "high",
                "detail": f"DKIM domain={dkim_dom} != From domain={from_domain}"
            })

        if dmarc and dmarc != "pass":
            findings.append({
                "issue": f"DMARC {dmarc}",
                "severity": "medium",
                "detail": ""
            })

        if arc and arc != "pass":
            findings.append({
                "issue": f"ARC chain issue ({arc})",
                "severity": "low",
                "detail": ""
            })

        # ----- Message-ID check -----
        if "Message-ID" not in headers:
            findings.append({
                "issue": "Missing Message-ID header",
                "severity": "medium",
                "detail": ""
            })

        # ----- Human-readable summary -----
        if findings:
            print("[!] Header anomalies detected:")
            for f in findings:
                print(f"   - {f['issue']} [{f['severity']}]")
        else:
            print("[+] Header analysis clean")

        return {
            "status": "done",
            "from_domain": from_domain,
            "auth": auth,
            "findings": findings
        }

    except Exception as e:
        print("[!] Header module error:", str(e))
        return {"status": "error", "error": str(e)}
