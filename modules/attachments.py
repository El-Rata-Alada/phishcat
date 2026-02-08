
def _check_deps():
    try:
        import email
        import zipfile
        return email, zipfile
    except ImportError as e:
        missing = str(e).split()[-1]
        print(f"[!] Missing dependency: {missing}")
        print(f"    Install using: pip install {missing}")
        return None, None


def main(msg):
    email, zipfile = _check_deps()
    if not email:
        return []

    findings = []

    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue

        filename_l = filename.lower()
        payload = part.get_payload(decode=True) or b""

        # ---------- HIGH RISK EXTENSIONS ----------
        if filename_l.endswith((
            ".exe", ".bat", ".cmd", ".scr",
            ".js", ".vbs", ".ps1", ".com", ".msi"
        )):
            findings.append({
                "file": filename,
                "severity": "HIGH",
                "reason": "Executable or script attachment"
            })
            continue

        # ---------- DOUBLE EXTENSION ----------
        parts = filename_l.split(".")
        if len(parts) > 2 and parts[-1] in (
            "exe", "js", "bat", "scr", "vbs", "ps1", "com"
        ):
            findings.append({
                "file": filename,
                "severity": "HIGH",
                "reason": "Double extension detected"
            })

        # ---------- ARCHIVES ----------
        if filename_l.endswith((".zip", ".rar", ".7z", ".iso")):
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "reason": "Archive attachment (manual inspection advised)"
            })

        # ---------- OFFICE MACROS (NOT DEFAULT SUS) ----------
        if filename_l.endswith((".docx", ".xlsx", ".pptx")):
            try:
                from io import BytesIO
                z = zipfile.ZipFile(BytesIO(payload))
                if "vbaProject.bin" in z.namelist():
                    findings.append({
                        "file": filename,
                        "severity": "HIGH",
                        "reason": "Office document contains VBA macros"
                    })
            except Exception:
                pass

        # ---------- PDF JAVASCRIPT (NOT DEFAULT SUS) ----------
        if filename_l.endswith(".pdf"):
            if b"/JavaScript" in payload or b"/JS" in payload:
                findings.append({
                    "file": filename,
                    "severity": "MEDIUM",
                    "reason": "PDF contains embedded JavaScript"
                })

        # ---------- MIME MISMATCH ----------
        ctype = part.get_content_type()
        if filename_l.endswith(".pdf") and ctype != "application/pdf":
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "reason": "MIME type mismatch for PDF"
            })

    return findings
