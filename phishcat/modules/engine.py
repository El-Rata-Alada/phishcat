from phishcat.modules import eml_loader
from phishcat.modules import headers
from phishcat.modules import body
from phishcat.modules import attachments
from phishcat.modules import report


def _save_report_if_needed(report_text: str):
    try:
        choice = input("\nSave report to file? (y/n): ").strip().lower()
        if choice == "y":
            with open("report.txt", "w", encoding="utf-8") as f:
                f.write(report_text)
            print("[+] Report saved as report.txt")
    except Exception as e:
        print(f"[!] Failed to save report: {e}")


def run_engine(eml_path: str) -> None:
    try:
        email_data = eml_loader.main(eml_path)
    except Exception as e:
        print(f"[!] Failed to load EML file: {e}")
        return

    header_findings = {}
    body_findings = {}
    attachment_findings = {}

    # -------------------------
    # Header analysis
    # -------------------------
    try:
        header_findings = headers.main(email_data.get("headers", {}))
    except Exception as e:
        print(f"[!] Header analysis failed: {e}")

    # -------------------------
    # Body analysis
    # -------------------------
    try:
        body_findings = body.main(email_data.get("bodies", {}))
    except Exception as e:
        print(f"[!] Body analysis failed: {e}")

    # -------------------------
    # Attachment analysis
    # -------------------------
    try:
        attachment_findings = attachments.main(
            email_data.get("attachments", [])
        )
    except Exception as e:
        print(f"[!] Attachment analysis failed: {e}")

    # -------------------------
    # Report generation
    # -------------------------
    try:
        report_text = report.main(
            header_findings,
            body_findings,
            attachment_findings
        )
        _save_report_if_needed(report_text)

    except Exception as e:
        print(f"[!] Report generation failed: {e}")
