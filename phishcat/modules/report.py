def _print_section(title, findings):
    print("\n" + "=" * 60)
    print(f"[ {title} ]")
    print("=" * 60)

    if not findings:
        print("No issues found.")
        return

    for i, item in enumerate(findings, 1):
        if isinstance(item, dict):
            print(f"\n{i}. {item.get('title', 'Finding')}")
            for k, v in item.items():
                if k == "title":
                    continue
                print(f"   - {k}: {v}")
        else:
            print(f"{i}. {item}")


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


def _print_attachments(attachment_data):
    print("\n" + "=" * 60)
    print("[ ATTACHMENTS ]")
    print("=" * 60)

    if not attachment_data or "files" not in attachment_data:
        print("No attachments found.")
        return

    files = attachment_data.get("files", [])

    if not files:
        print("No attachments found.")
        return

    for i, f in enumerate(files, 1):
        print(f"\n{i}. {f['filename']}")
        print(f"   Size: {f['size']}")

        hashes = f.get("hashes", {})
        if hashes:
            print("\n   Hashes:")
            print(f"     MD5    : {hashes.get('md5')}")
            print(f"     SHA1   : {hashes.get('sha1')}")
            print(f"     SHA256 : {hashes.get('sha256')}")
            print(f"     SHA512 : {hashes.get('sha512')}")

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

    # Headers
    _print_headers(header_findings)

    # Body
    _print_section("BODY", body_findings)

    # Attachments (fixed)
    _print_attachments(attachment_findings)

    print("\n" + "#" * 60)
    print("#                END OF REPORT                #")
    print("#" * 60)
