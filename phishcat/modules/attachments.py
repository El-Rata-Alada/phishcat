import hashlib


def _check_deps():
    try:
        import zipfile
        return zipfile
    except ImportError as e:
        missing = str(e).split()[-1]
        print(f"[!] Missing dependency: {missing}")
        print(f"    Install using: pip install {missing}")
        return None


def _hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def main(attachments):
    zipfile = _check_deps()
    if not zipfile:
        return []
        return {"files": [], "findings": []}

    files = []
    findings = []

    for att in attachments:
        filename = att.get("filename")
        if not filename:
            continue

    for part in attachments:
        filename = part.get("filename") or "unknown"
        payload = part.get("payload") or b""
        size = len(payload)
        filename_l = filename.lower()
        payload = att.get("payload") or b""
        ctype = att.get("content_type", "")

        file_info = {
            "filename": filename,
            "size": size,
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
                "reason": "Executable or script attachment"
                "reason": issue
            })
            continue

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
                "reason": "Double extension detected"
                "reason": issue
            })

        # ---------- ARCHIVES ----------
        if filename_l.endswith((".zip", ".rar", ".7z", ".iso")):
            issue = "Archive attachment (manual inspection advised)"
            file_info["findings"].append(issue)
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "reason": "Archive attachment (manual inspection advised)"
                "reason": issue
            })

        # ---------- OFFICE MACROS ----------
@@ -62,29 +83,30 @@ def main(attachments):
                from io import BytesIO
                z = zipfile.ZipFile(BytesIO(payload))
                if "vbaProject.bin" in z.namelist():
                    issue = "Office document contains VBA macros"
                    file_info["findings"].append(issue)
                    findings.append({
                        "file": filename,
                        "severity": "HIGH",
                        "reason": "Office document contains VBA macros"
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
                    "reason": "PDF contains embedded JavaScript"
                    "reason": issue
                })

        # ---------- MIME MISMATCH ----------
        if filename_l.endswith(".pdf") and ctype != "application/pdf":
            findings.append({
                "file": filename,
                "severity": "MEDIUM",
                "reason": "MIME type mismatch for PDF"
            })
        files.append(file_info)

    return findings
    return {
        "files": files,
        "findings": findings
    }
