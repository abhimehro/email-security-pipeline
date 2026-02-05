#!/usr/bin/env python3
"""
Lightweight IMAP/SMTP connectivity check using .env values.
Supports Gmail, Outlook (Business), and Proton Bridge.
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


def print_summary(results):
    if not results:
        return

    print(f"\n{Colors.BOLD}Connectivity Summary{Colors.RESET}")
    print("=" * 65)
    print(f"{Colors.BOLD}{'Provider':<15} {'Protocol':<10} {'Host:Port':<25} {'Status':<10}{Colors.RESET}")
    print("-" * 65)

    for res in results:
        provider = res.get('provider', 'Unknown')
        protocol = res.get('protocol', 'Unknown')
        host_port = f"{res.get('host')}:{res.get('port')}"
        success = res.get('success', False)

        status_color = Colors.GREEN if success else Colors.RED
        status_text = "OK" if success else "FAILED"
        status = Colors.colorize(status_text, status_color)

        print(f"{provider:<15} {protocol:<10} {host_port:<25} {status:<10}")

    print("=" * 65)
    print()


def check_imap(provider_name: str, host: str, port: int, use_ssl: bool, user: str, password: str, help_text: str = None):
    print_pending("IMAP", host, port, use_ssl)
    result = {
        'provider': provider_name,
        'protocol': 'IMAP',
        'host': host,
        'port': port,
        'success': False,
        'error': None
    }
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with imaplib.IMAP4_SSL(host, port, ssl_context=ctx) as imap:
                imap.login(user, password)
                imap.noop()
                print_status("IMAP", host, port, use_ssl, True)
                result['success'] = True
        else:
            with imaplib.IMAP4(host, port) as imap:
                imap.starttls()
                imap.login(user, password)
                imap.noop()
                print_status("IMAP", host, port, use_ssl, True)
                result['success'] = True
    except Exception as e:
        print_status("IMAP", host, port, use_ssl, False, str(e))
        result['error'] = str(e)
        if help_text:
            print(f"    {Colors.colorize('💡 Tip:', Colors.YELLOW)} {help_text}")

    return result


def check_smtp(provider_name: str, host: str, port: int, use_ssl: bool, user: str, password: str, help_text: str = None):
    print_pending("SMTP", host, port, use_ssl)
    result = {
        'provider': provider_name,
        'protocol': 'SMTP',
        'host': host,
        'port': port,
        'success': False,
        'error': None
    }
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx) as smtp:
                smtp.login(user, password)
                smtp.noop()
                print_status("SMTP", host, port, use_ssl, True)
                result['success'] = True
        else:
            with smtplib.SMTP(host, port) as smtp:
                smtp.starttls()
                smtp.login(user, password)
                smtp.noop()
                print_status("SMTP", host, port, use_ssl, True)
                result['success'] = True
    except Exception as e:
        print_status("SMTP", host, port, use_ssl, False, str(e))
        result['error'] = str(e)
        if help_text:
            print(f"    {Colors.colorize('💡 Tip:', Colors.YELLOW)} {help_text}")

    return result


def main():
    print(f"\n{Colors.BOLD}🔍 Checking Email Connectivity...{Colors.RESET}")

    any_enabled = False
    results = []

    # Gmail
    if os.getenv("GMAIL_ENABLED", "false").lower() == "true":
        any_enabled = True
        print_header("Gmail")

        gmail_help = "Check if 'App Password' is correct and IMAP is enabled in Gmail settings."

        results.append(check_imap(
            "Gmail",
            os.getenv("GMAIL_IMAP_SERVER", "imap.gmail.com"),
            int(os.getenv("GMAIL_IMAP_PORT", "993")),
            True,
            os.getenv("GMAIL_EMAIL", ""),
            os.getenv("GMAIL_APP_PASSWORD", ""),
            help_text=gmail_help
        ))
        results.append(check_smtp(
            "Gmail",
            os.getenv("GMAIL_SMTP_SERVER", "smtp.gmail.com"),
            int(os.getenv("GMAIL_SMTP_PORT", "465")),
            True,
            os.getenv("GMAIL_EMAIL", ""),
            os.getenv("GMAIL_APP_PASSWORD", ""),
            help_text=gmail_help
        ))

    # Outlook (Business/Enterprise)
    if os.getenv("OUTLOOK_ENABLED", "false").lower() == "true":
        any_enabled = True
        print_header("Outlook (Microsoft 365 Business)")

        outlook_help = "Personal Outlook accounts NO LONGER support App Passwords. Use Microsoft 365 Business accounts only."

        results.append(check_imap(
            "Outlook",
            os.getenv("OUTLOOK_IMAP_SERVER", "outlook.office365.com"),
            int(os.getenv("OUTLOOK_IMAP_PORT", "993")),
            True,
            os.getenv("OUTLOOK_EMAIL", ""),
            os.getenv("OUTLOOK_APP_PASSWORD", ""),
            help_text=outlook_help
        ))
        # Outlook SMTP typically uses STARTTLS on 587
        results.append(check_smtp(
            "Outlook",
            os.getenv("OUTLOOK_SMTP_SERVER", "smtp.office365.com"),
            int(os.getenv("OUTLOOK_SMTP_PORT", "587")),
            False, # Outlook SMTP usually uses STARTTLS
            os.getenv("OUTLOOK_EMAIL", ""),
            os.getenv("OUTLOOK_APP_PASSWORD", ""),
            help_text=outlook_help
        ))

    # Proton via Bridge
    if os.getenv("PROTON_ENABLED", "false").lower() == "true":
        any_enabled = True
        print_header("Proton Bridge")

        proton_help = "Ensure Proton Mail Bridge is running and serving localhost."

        results.append(check_imap(
            "Proton",
            os.getenv("PROTON_IMAP_SERVER", "127.0.0.1"),
            int(os.getenv("PROTON_IMAP_PORT", "1143")),
            False,
            os.getenv("PROTON_EMAIL", ""),
            os.getenv("PROTON_APP_PASSWORD", ""),
            help_text=proton_help
        ))
        results.append(check_smtp(
            "Proton",
            os.getenv("PROTON_SMTP_SERVER", "127.0.0.1"),
            int(os.getenv("PROTON_SMTP_PORT", "1025")),
            False,
            os.getenv("PROTON_EMAIL", ""),
            os.getenv("PROTON_APP_PASSWORD", ""),
            help_text=proton_help
        ))

    if results:
        print_summary(results)

    if not any_enabled:
        print(f"\n{Colors.colorize('⚠️  No email providers enabled in .env', Colors.YELLOW)}")
        print(f"   Please set {Colors.BOLD}GMAIL_ENABLED=true{Colors.RESET}, {Colors.BOLD}OUTLOOK_ENABLED=true{Colors.RESET}, or {Colors.BOLD}PROTON_ENABLED=true{Colors.RESET}")
    else:
        print(f"\n{Colors.BOLD}✨ Done.{Colors.RESET}\n")


if __name__ == "__main__":
    main()
