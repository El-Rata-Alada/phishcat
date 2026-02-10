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

    print("\n[ SENDER IDENTITIES ]")
    for key in ["From", "Reply-To", "Return-Path", "Sender", "Message-ID"]:
        val = identities.get(key)
        if val:
            print(f"{key}: {val}")

    print("\n[ AUTHENTICATION ]")
    for key in ["SPF", "DKIM", "DMARC", "ARC"]:
        print(f"{key}: {auth.get(key) or 'none'}")

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

    print(f"Status: {body_data.get('status')}")

    urls = body_data.get("urls", [])
    anchors = body_data.get("anchors", [])
    findings = body_data.get("findings", [])

    print(f"URLs found: {len(urls)}")
    print(f"Anchor links: {len(anchors)}")

    if findings:
        print("\nFindings:")
        for f in findings:
            print(f" - {f['issue']} [{f['severity']}]")
    else:
        print("\nFindings: none")


def _print_attachments(attachment_data):
    print("\n" + "=" * 60)
    print("[ ATTACHMENTS ]")
    print("=" * 60)

    if not attachment_data:
        print("No attachments.")
        return

    files = attachment_data.get("files", [])

    if not files:
        print("No attachments.")
        return

    for i, f in enumerate(files, 1):
        print(f"\n{i}. {f['filename']}")
        print(f"   Size: {f['size']} bytes")

        hashes = f.get("hashes", {})
        print("\n   Hashes:")
        for h in ["md5", "sha1", "sha256", "sha512"]:
            if h in hashes:
                print(f"     {h.upper():7}: {hashes[h]}")

        file_findings = f.get("findings", [])
        if file_findings:
            print("\n   Findings:")
            for issue in file_findings:
                print(f"     - {issue}")
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
