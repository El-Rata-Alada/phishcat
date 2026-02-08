
# Dependency check (stdlib only)
try:
    from email import policy
    from email.parser import BytesParser
except ImportError as e:
    print("[!] Missing standard library dependency:", e)
    print("    This should never happen. Check your Python installation.")
    raise


def main(eml_path: str) -> dict:
    """
    Load and parse a .eml file.
    Returns headers, bodies, and attachments.
    """

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = dict(msg.items())

    bodies = {
        "text/plain": [],
        "text/html": []
    }

    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()

        # Body parts
        if content_disposition is None and content_type in bodies:
            try:
                bodies[content_type].append(part.get_content())
            except Exception:
                continue

        # Attachments
        if content_disposition == "attachment":
            payload = part.get_payload(decode=True)

            attachments.append({
                "filename": part.get_filename(),
                "content_type": content_type,
                "size": len(payload) if payload else 0,
                "payload": payload
            })

    return {
        "headers": headers,
        "bodies": bodies,
        "attachments": attachments
    }
