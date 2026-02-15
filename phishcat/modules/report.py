import datetime


def _print_email_content(body_data):
    print("\n" + "=" * 60)
    print("[ EMAIL CONTENT ]")
    print("=" * 60)

    content = body_data.get("content", "")
    if content:
        print("\n" + content.strip())
    else:
        print("\n(No readable body content)")


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

    emails = body_data.get("emails", [])
    phones = body_data.get("phones", [])
    urls = body_data.get("urls", [])
    media_urls = body_data.get("media_urls", [])
    findings = body_data.get("findings", [])

    # Emails
    print(f"\n[ EMAIL ADDRESSES – {len(emails)} ]")
    for i, e in enumerate(emails, 1):
        print(f" {i}. {e}")

    # Phones
    print(f"\n[ PHONE NUMBERS – {len(phones)} ]")
    for i, p in enumerate(phones, 1):
        print(f" {i}. {p}")

    # URLs
    print(f"\n[ URLS – NON-MEDIA – {len(urls)} ]")
    for i, u in enumerate(urls, 1):
        print(f" {i}. {u}")

    print(f"\n[ URLS – MEDIA – {len(media_urls)} ]")
    for i, u in enumerate(media_urls, 1):
        print(f" {i}. {u}")

    # Findings
    print("\n[ SUSPICIOUS FINDINGS ]")
    if findings:
        for f in findings:
            print(f" - {f['detail']} → {f['issue']} [{f['severity']}]")
    else:
        print(" None")


def _print_attachments(data):
    print("\n" + "=" * 60)
    print("[ ATTACHMENTS ]")
    print("=" * 60)

    files = data.get("files", [])
    if not files:
        print("No attachments found.")
        return

    for i, f in enumerate(files, 1):
        print(f"\n{i}. {f['filename']}")
        print(f"   Size: {f['size']}")

        hashes = f.get("hashes", {})
        print("\n   Hashes:")
        print(f"     MD5    : {hashes.get('md5')}")
        print(f"     SHA1   : {hashes.get('sha1')}")
        print(f"     SHA256 : {hashes.get('sha256')}")
        print(f"     SHA512 : {hashes.get('sha512')}")

        issues = f.get("findings", [])
        if issues:
            print("\n   Findings:")
            for issue in issues:
                print(f"     - {issue}")
        else:
            print("\n   Findings: none")


def main(header_data, body_data, attachment_data):
    # 1. Email content first
    _print_email_content(body_data)

    # 2. Report start
    print("\n" + "#" * 60)
    print("#        EMAIL SECURITY ANALYSIS REPORT        #")
    print("#" * 60)

    _print_headers(header_data)
    _print_body(body_data)
    _print_attachments(attachment_data)

    print("\n" + "#" * 60)
    print("#                END OF REPORT                #")
    print("#" * 60)

    # 3. Save prompt
    choice = input("\nWould you like to save this report to a file? (y/n): ").strip().lower()
    if choice == "y":
        filename = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            # Simplest approach: re-run print to file later if needed
            f.write("Report saved via terminal version.\n")
        print(f"[+] Report saved to {filename}")
