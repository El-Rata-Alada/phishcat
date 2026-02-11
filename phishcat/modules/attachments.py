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


def main(attachments):
    zipfile = _check_deps()
    if not zipfile:
        return []

    results = []

    for part in attachments:
        filename = part.get("filename") or "unknown"
        payload = part.get("payload") or b""
        size = len(payload)
        filename_l = filename.lower()

        findings = []

        # ---------- HIGH RISK EXTENSIONS ----------
        if filename_l.endswith((
            ".exe", ".bat", ".cmd", ".scr",
            ".js", ".vbs", ".ps1", ".com", ".msi"
        )):
            findings.append("Executable or script attachment")

        # ---------- DOUBLE EXTENSION ----------
        parts = filename_l.split(".")
        if len(parts) > 2 and parts[-1] in (
            "exe", "js", "bat", "scr", "vbs", "ps1", "com"
        ):
            findings.append("Double extension detected")

        # ---------- ARCHIVES ----------
        if filename_l.endswith((".zip", ".rar", ".7z", ".iso")):
            findings.append("Archive attachment (manual inspection advised)")

        # ---------- OFFICE MACROS ----------
        if filename_l.endswith((".docx", ".xlsx", ".pptx")):
            try:
                from io import BytesIO
                z = zipfile.ZipFile(BytesIO(payload))
                if "vbaProject.bin" in z.namelist():
                    findings.append("Office document contains VBA macros")
            except Exception:
                pass

        # ---------- PDF JAVASCRIPT ----------
        if filename_l.endswith(".pdf"):
            if b"/JavaScript" in payload or b"/JS" in payload:
                findings.append("PDF contains embedded JavaScript")

        results.append({
            "title": filename,
            "size": size,
            "hashes": _hashes(payload),
            "findings": findings or ["none"]
        })

    return results
