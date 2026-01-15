#!/usr/bin/env python3
"""
Lightweight IMAP/SMTP connectivity check using .env values.
Supports Gmail and Proton Bridge (or any IMAP/SMTP endpoints you supply).
No messages are fetched or sent; we only attempt to open sockets and issue
minimal capability/NOOP commands.
"""

import os
import sys
import ssl
import imaplib
import smtplib
from pathlib import Path
from dotenv import load_dotenv

# Add project root to path to allow imports from src
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from src.utils.colors import Colors
except ImportError:
    # Fallback if import fails
    class Colors:
        RESET = ""
        BOLD = ""
        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        MAGENTA = ""
        CYAN = ""
        WHITE = ""
        GREY = ""
        @classmethod
        def colorize(cls, text, color): return text

load_dotenv()


def check_imap(label: str, host: str, port: int, use_ssl: bool, user: str, password: str):
    print(f"\n{Colors.BOLD}Checking IMAP: {label}{Colors.RESET} ({host}:{port}, SSL={use_ssl})...")
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with imaplib.IMAP4_SSL(host, port, ssl_context=ctx) as imap:
                imap.login(user, password)
                typ, data = imap.noop()
                print(f"  ✅ {Colors.colorize('Connected successfully', Colors.GREEN)}")
                print(f"     Response: {typ} {data}")
        else:
            with imaplib.IMAP4(host, port) as imap:
                imap.starttls()
                imap.login(user, password)
                typ, data = imap.noop()
                print(f"  ✅ {Colors.colorize('Connected successfully', Colors.GREEN)}")
                print(f"     Response: {typ} {data}")
    except Exception as e:
        print(f"  ❌ {Colors.colorize('Connection failed', Colors.RED)}")
        print(f"     Error: {e}")


def check_smtp(label: str, host: str, port: int, use_ssl: bool, user: str, password: str):
    print(f"\n{Colors.BOLD}Checking SMTP: {label}{Colors.RESET} ({host}:{port}, SSL={use_ssl})...")
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx) as smtp:
                smtp.login(user, password)
                smtp.noop()
                print(f"  ✅ {Colors.colorize('Connected successfully', Colors.GREEN)}")
        else:
            with smtplib.SMTP(host, port) as smtp:
                smtp.starttls()
                smtp.login(user, password)
                smtp.noop()
                print(f"  ✅ {Colors.colorize('Connected successfully', Colors.GREEN)}")
    except Exception as e:
        print(f"  ❌ {Colors.colorize('Connection failed', Colors.RED)}")
        print(f"     Error: {e}")


def main():
    print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.RESET}")
    print("Email Connectivity Check")
    print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.RESET}")

    # Gmail
    if os.getenv("GMAIL_ENABLED", "false").lower() == "true":
        check_imap(
            "Gmail",
            os.getenv("GMAIL_IMAP_SERVER", "imap.gmail.com"),
            int(os.getenv("GMAIL_IMAP_PORT", "993")),
            True,
            os.getenv("GMAIL_EMAIL", ""),
            os.getenv("GMAIL_APP_PASSWORD", ""),
        )
        check_smtp(
            "Gmail",
            os.getenv("GMAIL_SMTP_SERVER", "smtp.gmail.com"),
            int(os.getenv("GMAIL_SMTP_PORT", "465")),
            True,
            os.getenv("GMAIL_EMAIL", ""),
            os.getenv("GMAIL_APP_PASSWORD", ""),
        )

    # Proton via Bridge (defaults to SSL on 143/1025 per user; adjust if STARTTLS on 1143/SMTP 1025)
    if os.getenv("PROTON_ENABLED", "false").lower() == "true":
        check_imap(
            "Proton Bridge",
            os.getenv("PROTON_IMAP_SERVER", "127.0.0.1"),
            int(os.getenv("PROTON_IMAP_PORT", "1143")),
            False,
            os.getenv("PROTON_EMAIL", ""),
            os.getenv("PROTON_APP_PASSWORD", ""),
        )
        check_smtp(
            "Proton Bridge",
            os.getenv("PROTON_SMTP_SERVER", "127.0.0.1"),
            int(os.getenv("PROTON_SMTP_PORT", "1025")),
            False,
            os.getenv("PROTON_EMAIL", ""),
            os.getenv("PROTON_APP_PASSWORD", ""),
        )

    print(f"\n{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.RESET}")
    print(f"Check complete.{Colors.RESET}")


if __name__ == "__main__":
    main()
