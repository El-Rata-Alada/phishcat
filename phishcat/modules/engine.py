from phishcat.modules import eml_loader
from phishcat.modules import headers
from phishcat.modules import body
from phishcat.modules import attachments
from phishcat.modules import report


def _print_email_content(email_data, body_data):
    print("\n" + "=" * 60)
    print("[ EMAIL CONTENT ]")
    print("=" * 60)

    bodies = email_data.get("bodies", {})
    text = "\n".join(bodies.get("text/plain", []))
    html = "\n".join(bodies.get("text/html", []))

    readable = text.strip() or html.strip()

    if readable:
        print("\n" + readable[:2000])
        if len(readable) > 2000:
            print("\n...[truncated]")
    else:
        print("\n(No readable body content)")

    # ---- print all URLs ----
    urls = body_data.get("urls", [])
    print("\n" + "=" * 60)
    print(f"[ ALL URLS FOUND – {len(urls)} ]")
    print("=" * 60)

    for i, url in enumerate(urls, 1):
        print(f"{i}. {url}")


def run_engine(eml_path: str) -> None:
    try:
        email_data = eml_loader.main(eml_path)
    except Exception as e:
        print(f"[!] Failed to load EML file: {e}")
        return

    try:
        body_data = body.main(email_data.get("bodies", {}))
    except Exception as e:
        print(f"[!] Body analysis failed: {e}")
        body_data = {"status": "error"}

    # ---- show readable email + URLs BEFORE report ----
    _print_email_content(email_data, body_data)

    try:
        header_findings = headers.main(email_data.get("headers", {}))
    except Exception as e:
        print(f"[!] Header analysis failed: {e}")
        header_findings = {}

    try:
        attachment_findings = attachments.main(
            email_data.get("attachments", [])
        )
    except Exception as e:
        print(f"[!] Attachment analysis failed: {e}")
        attachment_findings = {}

    # ---- final report ----
    report.main(
        header_findings,
        body_data,
        attachment_findings
    )
