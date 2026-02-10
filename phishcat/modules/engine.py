from phishcat.modules import eml_loader
from phishcat.modules import headers
from phishcat.modules import body
from phishcat.modules import attachments
from phishcat.modules import report


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

    try:
        report.main(
            header_findings,
            body_findings,
            attachment_findings
        )
    except Exception as e:
        print(f"[!] Report generation failed: {e}")
