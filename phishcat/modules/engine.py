from phishcat.modules import eml_loader
from phishcat.modules import headers
from phishcat.modules import body
from phishcat.modules import attachments
from phishcat.modules import report


def _print_email_content(email_data):
    """Print the email body as seen in inbox."""
    bodies = email_data.get("bodies", {})

    text_parts = bodies.get("text/plain", [])
    html_parts = bodies.get("text/html", [])

    print("\n" + "=" * 60)
    print("[ EMAIL CONTENT ]")
    print("=" * 60)

    # Prefer plain text
    if text_parts:
        print(text_parts[0].strip())
    elif html_parts:
        # fallback: show raw html stripped roughly
        import re
        html = html_parts[0]
        text = re.sub(r"<[^>]+>", "", html)
        print(text.strip())
    else:
        print("(No readable body content)")


def _print_all_urls(body_data):
    urls = body_data.get("urls", [])
    anchors = body_data.get("anchors", [])

    all_urls = sorted(set(urls + anchors))

    print("\n" + "=" * 60)
    print(f"[ ALL URLS FOUND – {len(all_urls)} ]")
    print("=" * 60)

    if not all_urls:
        print("No URLs found.")
        return

    for i, u in enumerate(all_urls, 1):
        print(f"{i}. {u}")


def run_engine(eml_path: str) -> None:
    try:
        email_data = eml_loader.main(eml_path)
    except Exception as e:
        print(f"[!] Failed to load EML file: {e}")
        return

    header_findings = []
    body_findings = []
    attachment_findings = []

    try:
        header_findings = headers.main(email_data.get("headers", {}))
    except Exception as e:
        print(f"[!] Header analysis failed: {e}")

    try:
        body_findings = body.main(email_data.get("bodies", {}))
    except Exception as e:
        print(f"[!] Body analysis failed: {e}")

    try:
        attachment_findings = attachments.main(
            email_data.get("attachments", [])
        )
    except Exception as e:
        print(f"[!] Attachment analysis failed: {e}")

    # -------------------------
    # NEW: Pre-report output
    # -------------------------
    _print_email_content(email_data)
    _print_all_urls(body_findings)

    # -------------------------
    # Existing report
    # -------------------------
    try:
        report.main(
            header_findings,
            body_findings,
            attachment_findings
        )
    except Exception as e:
        print(f"[!] Report generation failed: {e}")
