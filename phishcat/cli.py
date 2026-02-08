#!/usr/bin/env python3

import sys
import os

from modules.engine import run_engine


def banner():
    print("""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ █████╗ ████████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝
██████╔╝███████║██║███████╗███████║██║     ███████║   ██║   
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║     ██╔══██║   ██║   
██║     ██║  ██║██║███████║██║  ██║╚██████╗██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   

        Email Threat Analyzer
    """)


def usage():
    print("Usage:")
    print("  phishcat <file.eml>")


def main():
    banner()

    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    eml_path = sys.argv[1]

    if not os.path.isfile(eml_path):
        print(f"[!] File not found: {eml_path}")
        sys.exit(1)

    if not eml_path.lower().endswith(".eml"):
        print("[!] Input must be a .eml file")
        sys.exit(1)

    print(f"[+] Analyzing: {eml_path}\n")

    run_engine(eml_path)


if __name__ == "__main__":
    main()

