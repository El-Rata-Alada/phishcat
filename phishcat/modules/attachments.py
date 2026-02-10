def _check_deps():
    try:
        import zipfile
        return zipfile
    except ImportError as e:
        missing = str(e).split()[-1]
        print(f"[!] Missing dependency: {missing}")
        print(f"    Install using: pip install {missing}")
        return None


def main(attachments):
    zipfile = _check_deps()
    if not zipfile:
        return []

    findings = []

    for att in attachments:
        filename = att.get("filename")
        if not filename:
            continue

        filename_l = filename.lower()
        payload = att.get("payload") or b""
        ctype = att.get("content_type", "")

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

        # ---------- OFFICE MACROS ----------
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

        # ---------- PDF JAVASCRIPT ----------
        if filename_l.endswith(".pdf"):
            if b"/JavaScript" in payload or b"/JS" in payload:
                findings.append({
                    "file": filename,
                    "severity": "MEDIUM",
                    "reason": "PDF contains embedded JavaScript"
                })

        # ---------- MIME MISMATCH ----------
        if filename_l.endswith(".pdf") and ctype != "application/pdf":
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "reason": "MIME type mismatch for PDF"
            })

    return findings
