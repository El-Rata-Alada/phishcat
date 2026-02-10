def main(eml_path: str) -> dict:
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = dict(msg.items())

    bodies = {
        "text": "",
        "html": ""
    }

    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()

        # Body parts
        if content_disposition is None:
            try:
                if content_type == "text/plain":
                    bodies["text"] += part.get_content()
                elif content_type == "text/html":
                    bodies["html"] += part.get_content()
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
