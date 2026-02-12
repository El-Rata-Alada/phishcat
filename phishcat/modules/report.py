def _format_size(size_bytes: int) -> str:
    """Convert size to bytes, KB, or MB automatically."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def _print_headers(header_data):
    print("\n" + "=" * 60)
    print("[ HEADERS ]")
    print("=" * 60)

    if not header_data or header_data.get("status") == "error":
        print("Header analysis failed.")
        return

    identities = header_data.get("identities", {})
    auth = header_data.get("auth", {})
    findings = header_data.get("findings", [])

    # ---- Sender identities ----
    print("\n[ SENDER IDENTITIES ]")
    for key in ["From", "Reply-To", "Return-Path", "Sender", "Message-ID"]:
        value = identities.get(key)
        if value:
            print(f"{key}: {value}")

    # ---- Authentication ----
    print("\n[ AUTHENTICATION ]")
    for key in ["SPF", "DKIM", "DMARC", "ARC"]:
        val = auth.get(key)
        print(f"{key}: {val or 'none'}")

    # ---- Findings ----
    print("\n[ FINDINGS ]")
    if findings:
        for f in findings:
            print(f" - {f['issue']} [{f['severity']}]")
    else:
        print(" None")


def _print_body(body_data):
    print("\n" + "=" * 60)
    print("[ BODY ]")
    print("=" * 60)

    if not body_data or body_data.get("status") == "error":
        print("Body analysis failed.")
        return

    urls = body_data.get("urls", [])
    emails = body_data.get("emails", [])
    phones = body_data.get("phones", [])
    suspicious = body_data.get("findings", [])

    print(f"\nURLs found: {len(urls)}")
    print(f"Email addresses found: {len(emails)}")
    print(f"Phone numbers found: {len(phones)}")

    print("\n[ SUSPICIOUS FINDINGS ]")
    if suspicious:
        for f in suspicious:
            issue = f.get("issue")
            severity = f.get("severity")
            detail = f.get("detail", {})
            value = detail.get("url") or detail.get("value") or ""
            print(f" - {value} → {issue} [{severity}]")
    else:
        print(" None")


def _print_attachments(att_data):
    print("\n" + "=" * 60)
    print("[ ATTACHMENTS ]")
    print("=" * 60)

    if not att_data or not att_data.get("files"):
        print("No attachments found.")
        return

    files = att_data.get("files", [])

    for i, f in enumerate(files, 1):
        print(f"\n{i}. {f['filename']}")

        size_str = _format_size(f.get("size", 0))
        print(f"   Size: {size_str}")

        hashes = f.get("hashes", {})
        print("\n   Hashes:")
        print(f"\n     MD5    : {hashes.get('md5')}")
        print(f"\n     SHA1   : {hashes.get('sha1')}")
        print(f"\n     SHA256 : {hashes.get('sha256')}")
        print(f"\n     SHA512 : {hashes.get('sha512')}")

        findings = f.get("findings", [])
        if findings:
            print("\n   Findings:")
            for item in findings:
                print(f"     - {item}")
        else:
            print("\n   Findings: none")


def main(header_findings, body_findings, attachment_findings):
    print("\n" + "#" * 60)
    print("#        EMAIL SECURITY ANALYSIS REPORT        #")
    print("#" * 60)

    _print_headers(header_findings)
    _print_body(body_findings)
    _print_attachments(attachment_findings)

    print("\n" + "#" * 60)
    print("#                END OF REPORT                #")
    print("#" * 60)
