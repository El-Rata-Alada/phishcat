import hashlib


def _check_deps():
    try:
        import zipfile
        return zipfile
    except ImportError as e:
        missing = str(e).split()[-1]
        print(f"[!] Missing dependency: {missing}")
        return None


def _hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    elif size < 1024 * 1024:
        return f"{round(size / 1024, 2)} KB"
    else:
        return f"{round(size / (1024 * 1024), 2)} MB"


def main(attachments):
    zipfile = _check_deps()
    if not zipfile:
        return {"files": [], "findings": []}

    files = []
    findings = []

    for part in attachments:
        filename = part.get("filename") or "unknown"
        payload = part.get("payload") or b""
        size = len(payload)
        filename_l = filename.lower()

        file_info = {
            "filename": filename,
            "size": _format_size(size),
            "hashes": _hashes(payload),
            "findings": []
        }

        # ---------- HIGH RISK EXTENSIONS ----------
        if filename_l.endswith((
            ".exe", ".bat", ".cmd", ".scr",
            ".js", ".vbs", ".ps1", ".com", ".msi"
        )):
            issue = "Executable or script attachment"
            file_info["findings"].append(issue)
            findings.append({
                "file": filename,
                "severity": "HIGH",
                "reason": issue
            })

        # ---------- DOUBLE EXTENSION ----------
        parts = filename_l.split(".")
        if len(parts) > 2 and parts[-1] in (
            "exe", "js", "bat", "scr", "vbs", "ps1", "com"
        ):
            issue = "Double extension detected"
            file_info["findings"].append(issue)
            findings.append({
                "file": filename,
                "severity": "HIGH",
                "reason": issue
            })

        # ---------- ARCHIVES ----------
        if filename_l.endswith((".zip", ".rar", ".7z", ".iso")):
            issue = "Archive attachment (manual inspection advised)"
            file_info["findings"].append(issue)
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "reason": issue
            })

        # ---------- OFFICE MACROS ----------
        if filename_l.endswith((".docx", ".xlsx", ".pptx")):
            try:
                from io import BytesIO
                z = zipfile.ZipFile(BytesIO(payload))
                if "vbaProject.bin" in z.namelist():
                    issue = "Office document contains VBA macros"
                    file_info["findings"].append(issue)
                    findings.append({
                        "file": filename,
                        "severity": "HIGH",
                        "reason": issue
                    })
            except Exception:
                pass

        # ---------- PDF JAVASCRIPT ----------
        if filename_l.endswith(".pdf"):
            if b"/JavaScript" in payload or b"/JS" in payload:
                issue = "PDF contains embedded JavaScript"
                file_info["findings"].append(issue)
                findings.append({
                    "file": filename,
                    "severity": "MEDIUM",
                    "reason": issue
                })

        files.append(file_info)

    return {
        "files": files,
        "findings": findings
    }
