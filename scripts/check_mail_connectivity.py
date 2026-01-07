#!/usr/bin/env python3
"""
Lightweight IMAP/SMTP connectivity check using .env values.
Supports Gmail and Proton Bridge (or any IMAP/SMTP endpoints you supply).
No messages are fetched or sent; we only attempt to open sockets and issue
minimal capability/NOOP commands.
"""

import os
import ssl
import imaplib
import smtplib
from dotenv import load_dotenv

load_dotenv()


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(message):
    print(f"\n{Colors.BOLD}{Colors.BLUE}== {message} =={Colors.RESET}")


def print_success(message):
    print(f"  {Colors.GREEN}✅ {message}{Colors.RESET}")


def print_error(message):
    print(f"  {Colors.RED}❌ {message}{Colors.RESET}")


def print_info(message):
    print(f"  {Colors.YELLOW}ℹ️  {message}{Colors.RESET}")


def check_imap(label: str, host: str, port: int, use_ssl: bool, user: str, password: str):
    print_header(f"IMAP: {label} ({host}:{port}, SSL={use_ssl})")

    if not user or not password:
        print_info("Skipping: Credentials not set")
        return

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with imaplib.IMAP4_SSL(host, port, ssl_context=ctx) as imap:
                imap.login(user, password)
                typ, data = imap.noop()
                print_success(f"OK NOOP: {typ} {data}")
        else:
            with imaplib.IMAP4(host, port) as imap:
                imap.starttls()
                imap.login(user, password)
                typ, data = imap.noop()
                print_success(f"OK NOOP: {typ} {data}")
    except Exception as e:
        print_error(f"Connection failed: {e}")


def check_smtp(label: str, host: str, port: int, use_ssl: bool, user: str, password: str):
    print_header(f"SMTP: {label} ({host}:{port}, SSL={use_ssl})")

    if not user or not password:
        print_info("Skipping: Credentials not set")
        return

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx) as smtp:
                smtp.login(user, password)
                smtp.noop()
                print_success("OK NOOP")
        else:
            with smtplib.SMTP(host, port) as smtp:
                smtp.starttls()
                smtp.login(user, password)
                smtp.noop()
                print_success("OK NOOP")
    except Exception as e:
        print_error(f"Connection failed: {e}")


def main():
    print(f"{Colors.BOLD}🔍 Starting Connectivity Checks...{Colors.RESET}")

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
    else:
        print_info("Gmail checks skipped (GMAIL_ENABLED != true)")

    # Proton via Bridge
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
    else:
        print_info("Proton checks skipped (PROTON_ENABLED != true)")

    print(f"\n{Colors.BOLD}✨ Connectivity checks complete.{Colors.RESET}")


if __name__ == "__main__":
    main()
