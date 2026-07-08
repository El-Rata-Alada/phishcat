import hashlib
import os
import subprocess


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


def _inspect_true_type(payload: bytes) -> str:
    """Uses the built-in system 'file' command to check raw data signatures."""
    if not payload:
        return "empty"
    # Runs native system tool feeding the raw bytes directly via pipeline ("-")
    result = subprocess.run(
        ["file", "--brief", "-"], 
        input=payload, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE
    )
    return result.stdout.decode('utf-8', errors='ignore').strip().lower()


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

        # ---------- AUTOMATED SYSTEM HEX BYTE VERIFICATION ----------
        true_type = _inspect_true_type(payload)
        _, ext = os.path.splitext(filename_l)

        is_spoof_suspected = False
        reason_msg = ""

        if ext == ".pdf" and "pdf document" not in true_type:
            is_spoof_suspected = True
        elif ext in [".docx", ".xlsx", ".pptx", ".zip"] and "zip archive" not in true_type:
            is_spoof_suspected = True
        
        # Check if a non-executable extension is structurally masking binary executable code
        if ext not in [".exe", ".scr", ".com", ".bat"] and ("executable" in true_type or "pe32" in true_type):
            is_spoof_suspected = True
            reason_msg = f"Critical Extension Spoofing: Claims to be '{ext}' but system magic bits show it is an Executable binary."
        elif is_spoof_suspected:
            reason_msg = f"Mismatched File Type: Extension is '{ext}' but system reports content signature behaves as '{true_type}'."

        if is_spoof_suspected and reason_msg:
            file_info["findings"].append(reason_msg)
            findings.append({
                "file": filename,
                "severity": "CRITICAL" if "executable" in true_type else "HIGH",
                "reason": reason_msg
            })

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
