import sys
from email import policy
from email.parser import BytesParser

def parse_eml(path):
    with open(path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg.items()

def parse_pasted_headers():
    print("Paste email headers (end with CTRL+D):\n")
    raw = sys.stdin.read()
    headers = []
    for line in raw.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            headers.append((key.strip(), value.strip()))
    return headers

def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python email_scanner.py <file.eml>")
        print("  python email_scanner.py paste")
        return

    if sys.argv[1].endswith(".eml"):
        headers = parse_eml(sys.argv[1])
    elif sys.argv[1] == "paste":
        headers = parse_pasted_headers()
    else:
        print("Invalid input")
        return

    print("\n--- Parsed Email Headers ---\n")
    for k, v in headers:
        print(f"{k}: {v}")

if __name__ == "__main__":
    main()
