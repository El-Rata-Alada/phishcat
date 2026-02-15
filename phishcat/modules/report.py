def main(header_data, body_data, attachment_data):
    lines = []

    def p(text=""):
        print(text)
        lines.append(text)

    # ------------------------------------------------
    # REPORT HEADER
    # ------------------------------------------------
    p("\n" + "#" * 60)
    p("#        EMAIL SECURITY ANALYSIS REPORT        #")
    p("#" * 60)

    # ------------------------------------------------
    # HEADERS SECTION
    # ------------------------------------------------
    p("\n" + "=" * 60)
    p("[ HEADERS ]")
    p("=" * 60)

    if not header_data or header_data.get("status") == "error":
        p("Header analysis failed.")
    else:
        identities = header_data.get("identities", {})
        auth = header_data.get("auth", {})
        findings = header_data.get("findings", [])

        p("\n[ SENDER IDENTITIES ]")
        for key in ["From", "Reply-To", "Return-Path", "Sender", "Message-ID"]:
            value = identities.get(key)
            if value:
                p(f"{key}: {value}")

        p("\n[ AUTHENTICATION ]")
        for key in ["SPF", "DKIM", "DMARC", "ARC"]:
            val = auth.get(key)
            p(f"{key}: {val or 'none'}")

        p("\n[ FINDINGS ]")
        if findings:
            for f in findings:
                p(f" - {f['issue']} [{f['severity']}]")
        else:
            p(" None")

    # ------------------------------------------------
    # BODY SECTION
    # ------------------------------------------------
    p("\n" + "=" * 60)
    p("[ BODY ]")
    p("=" * 60)

    if not body_data or body_data.get("status") == "error":
        p("Body analysis failed.")
    else:
        urls = sorted(body_data.get("urls", []))
        anchors = sorted(body_data.get("anchors", []))
        emails = sorted(body_data.get("emails", []))
        phones = sorted(body_data.get("phones", []))
        findings = body_data.get("findings", [])

        # URLs
        all_urls = sorted(set(urls + anchors))
        p(f"\nURLs found: {len(all_urls)}")
        for u in all_urls:
            p(f" - {u}")

        # Emails
        p(f"\nEmail addresses found: {len(emails)}")
        for e in emails:
            p(f" - {e}")

        # Phones
        p(f"\nPhone numbers found: {len(phones)}")
        for ph in phones:
            p(f" - {ph}")

        # Suspicious findings
        p("\n[ SUSPICIOUS FINDINGS ]")
        if findings:
            for f in findings:
                detail = f.get("detail", {})
                value = detail.get("url") or detail.get("value") or ""
                p(f" - {value} → {f['issue']} [{f['severity']}]")
        else:
            p(" None")

    # ------------------------------------------------
    # ATTACHMENTS SECTION
    # ------------------------------------------------
    p("\n" + "=" * 60)
    p("[ ATTACHMENTS ]")
    p("=" * 60)

    if not attachment_data or "files" not in attachment_data:
        p("No attachments found.")
    else:
        files = attachment_data.get("files", [])

        if not files:
            p("No attachments found.")
        else:
            for i, f in enumerate(files, 1):
                p(f"\n{i}. {f['filename']}")
                p(f"   Size: {f['size']}")

                hashes = f.get("hashes", {})
                if hashes:
                    p("\n   Hashes:")
                    p(f"     MD5    : {hashes.get('md5')}")
                    p(f"     SHA1   : {hashes.get('sha1')}")
                    p(f"     SHA256 : {hashes.get('sha256')}")
                    p(f"     SHA512 : {hashes.get('sha512')}")

                file_findings = f.get("findings", [])
                if file_findings:
                    p("\n   Findings:")
                    for issue in file_findings:
                        p(f"     - {issue}")
                else:
                    p("\n   Findings: none")

    # ------------------------------------------------
    # END
    # ------------------------------------------------
    p("\n" + "#" * 60)
    p("#                END OF REPORT                #")
    p("#" * 60)

    return "\n".join(lines)
