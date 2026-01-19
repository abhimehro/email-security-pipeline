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
from dotenv import load_dotenv

# Add parent directory to path to import src
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from src.utils.colors import Colors
except ImportError:
    # Fallback if src not found or not in path
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
        def colorize(cls, text, color):
            return text

load_dotenv()


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.colorize(text, Colors.BLUE)}{Colors.RESET}")


def print_pending(protocol, host, port, use_ssl):
    ssl_str = "SSL" if use_ssl else "STARTTLS"
    print(f"  ⏳ {protocol:<4} ({host}:{port}, {ssl_str}) ...", end="\r")
    sys.stdout.flush()


def print_status(protocol, host, port, use_ssl, success, message=None):
    # Clear line to prevent artifacts
    print(" " * 80, end="\r")

    symbol = "✅" if success else "❌"
    color = Colors.GREEN if success else Colors.RED
    status = Colors.colorize("OK", color) if success else Colors.colorize("ERROR", color)
    ssl_str = "SSL" if use_ssl else "STARTTLS"

    print(f"  {symbol} {protocol:<4} ({host}:{port}, {ssl_str}) -> {status}")

    if not success and message:
        print(f"    {Colors.colorize('Error:', Colors.RED)} {message}")


def check_imap(host: str, port: int, use_ssl: bool, user: str, password: str):
    print_pending("IMAP", host, port, use_ssl)
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with imaplib.IMAP4_SSL(host, port, ssl_context=ctx) as imap:
                imap.login(user, password)
                typ, data = imap.noop()
                print_status("IMAP", host, port, use_ssl, True)
        else:
            with imaplib.IMAP4(host, port) as imap:
                imap.starttls()
                imap.login(user, password)
                typ, data = imap.noop()
                print_status("IMAP", host, port, use_ssl, True)
    except Exception as e:
        print_status("IMAP", host, port, use_ssl, False, str(e))


def check_smtp(host: str, port: int, use_ssl: bool, user: str, password: str):
    print_pending("SMTP", host, port, use_ssl)
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx) as smtp:
                smtp.login(user, password)
                smtp.noop()
                print_status("SMTP", host, port, use_ssl, True)
        else:
            with smtplib.SMTP(host, port) as smtp:
                smtp.starttls()
                smtp.login(user, password)
                smtp.noop()
                print_status("SMTP", host, port, use_ssl, True)
    except Exception as e:
        print_status("SMTP", host, port, use_ssl, False, str(e))


def main():
    print(f"\n{Colors.BOLD}🔍 Checking Email Connectivity...{Colors.RESET}")

    any_enabled = False

    # Gmail
    if os.getenv("GMAIL_ENABLED", "false").lower() == "true":
        any_enabled = True
        print_header("Gmail")

        check_imap(
            os.getenv("GMAIL_IMAP_SERVER", "imap.gmail.com"),
            int(os.getenv("GMAIL_IMAP_PORT", "993")),
            True,
            os.getenv("GMAIL_EMAIL", ""),
            os.getenv("GMAIL_APP_PASSWORD", ""),
        )
        check_smtp(
            os.getenv("GMAIL_SMTP_SERVER", "smtp.gmail.com"),
            int(os.getenv("GMAIL_SMTP_PORT", "465")),
            True,
            os.getenv("GMAIL_EMAIL", ""),
            os.getenv("GMAIL_APP_PASSWORD", ""),
        )

    # Proton via Bridge
    if os.getenv("PROTON_ENABLED", "false").lower() == "true":
        any_enabled = True
        print_header("Proton Bridge")

        check_imap(
            os.getenv("PROTON_IMAP_SERVER", "127.0.0.1"),
            int(os.getenv("PROTON_IMAP_PORT", "1143")),
            False,
            os.getenv("PROTON_EMAIL", ""),
            os.getenv("PROTON_APP_PASSWORD", ""),
        )
        check_smtp(
            os.getenv("PROTON_SMTP_SERVER", "127.0.0.1"),
            int(os.getenv("PROTON_SMTP_PORT", "1025")),
            False,
            os.getenv("PROTON_EMAIL", ""),
            os.getenv("PROTON_APP_PASSWORD", ""),
        )

    if not any_enabled:
        print(f"\n{Colors.colorize('⚠️  No email providers enabled in .env', Colors.YELLOW)}")
        print(f"   Please set {Colors.BOLD}GMAIL_ENABLED=true{Colors.RESET} or {Colors.BOLD}PROTON_ENABLED=true{Colors.RESET}")
    else:
        print(f"\n{Colors.BOLD}✨ Done.{Colors.RESET}\n")


if __name__ == "__main__":
    main()
