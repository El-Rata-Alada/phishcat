#this file will be empty for now.
#thanks for visiting
def _print_section(title, findings):
    print("\n" + "=" * 60)
    print(f"[ {title} ]")
    print("=" * 60)

    if not findings:
        print("No issues found.")
        return

    for i, item in enumerate(findings, 1):
        if isinstance(item, dict):
            print(f"\n{i}. {item.get('title', 'Finding')}")
            for k, v in item.items():
                if k == "title":
                    continue
                print(f"   - {k}: {v}")
        else:
            print(f"{i}. {item}")


def main(header_findings, body_findings, attachment_findings):
    print("\n" + "#" * 60)
    print("#        EMAIL SECURITY ANALYSIS REPORT        #")
    print("#" * 60)

    _print_section("HEADERS", header_findings)
    _print_section("BODY", body_findings)
    _print_section("ATTACHMENTS", attachment_findings)

    print("\n" + "#" * 60)
    print("#                END OF REPORT                #")
    print("#" * 60)
