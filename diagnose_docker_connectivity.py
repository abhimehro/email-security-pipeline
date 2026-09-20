#!/usr/bin/env python3
"""
Diagnostic script to test email connectivity from within Docker container context.
This helps identify whether issues are credential-based or network/SSL-based.
"""

import imaplib
import os
import ssl
import sys
from dataclasses import dataclass

from dotenv import load_dotenv

from src.utils.colors import Colors
from src.utils.security_validators import validate_mail_server_host


@dataclass
class ConnectionConfig:
    label: str
    host: str
    port: int
    email: str
    password: str
    use_ssl: bool = True
    verify_ssl: bool = True


def _create_ssl_context(verify_ssl: bool):
    """Create an SSL context, optionally disabling certificate verification."""
    if verify_ssl:
        return ssl.create_default_context()

    print(Colors.colorize("⚠  SSL verification DISABLED", Colors.YELLOW))
    return ssl._create_unverified_context()  # nosec B323


def _create_imap_client(config: ConnectionConfig):
    """Create an IMAP client based on SSL/STARTTLS configuration."""
    if config.use_ssl:
        context = _create_ssl_context(config.verify_ssl)
        print(f"Connecting to {config.host}:{config.port} with SSL...")
        return imaplib.IMAP4_SSL(
            config.host, config.port, ssl_context=context, timeout=30
        )

    print(f"Connecting to {config.host}:{config.port} without SSL...")
    imap = imaplib.IMAP4(config.host, config.port, timeout=30)
    print("Upgrading to TLS...")
    imap.starttls(ssl_context=_create_ssl_context(config.verify_ssl))
    return imap


def test_connection(config: ConnectionConfig):
    """Test IMAP connection with detailed diagnostics."""
    try:
        config.host = validate_mail_server_host(config.host)
    except ValueError as e:
        print(f"\n{'='*60}")
        print(f"Testing: {config.label}")
        print(Colors.colorize(f"✖ Security Error: {e}", Colors.RED))
        print(f"{'='*60}")
        return False

    print(f"\n{'='*60}")
    print(f"Testing: {config.label}")
    print(f"Host: {config.host}:{config.port}")
    print(f"Email: {config.email}")
    print(f"SSL: {config.use_ssl}, Verify: {config.verify_ssl}")
    print(f"{'='*60}")

    try:
        imap = _create_imap_client(config)
        print(Colors.colorize("✔ Connection established", Colors.GREEN))
        print(f"Logging in as {config.email}...")

        imap.login(config.email, config.password)
        print(Colors.colorize("✔ SUCCESS - Authentication successful!", Colors.GREEN))

        # Try to list folders
        status, folders = imap.list()
        if status == "OK":
            print(Colors.colorize(f"✔ Found {len(folders)} folders", Colors.GREEN))

        imap.logout()
        return True

    except imaplib.IMAP4.error as e:
        print(Colors.colorize(f"✖ IMAP Error: {e}", Colors.RED))
        if config.label.startswith("Outlook"):
            print(
                Colors.colorize(
                    "   Tip: Personal Outlook accounts NO LONGER support App Passwords.",
                    Colors.YELLOW,
                )
            )
    except ssl.SSLError as e:
        print(Colors.colorize(f"✖ SSL Error: {e}", Colors.RED))
        print(f"   Error type: {type(e).__name__}")
        print(f"   Error args: {e.args}")
    except Exception as e:
        print(Colors.colorize(f"✖ Unexpected Error: {e}", Colors.RED))
        print(f"   Error type: {type(e).__name__}")

    return False


def _test_gmail_account(results: list) -> None:
    """Run connection diagnostics for Gmail if enabled."""
    if os.getenv("GMAIL_ENABLED", "").lower() != "true":
        return

    gmail_email = os.getenv("GMAIL_EMAIL", "")
    gmail_password = os.getenv("GMAIL_APP_PASSWORD", "")

    if gmail_email and gmail_password:
        results.append(
            test_connection(
                ConnectionConfig(
                    "Gmail",
                    os.getenv("GMAIL_IMAP_SERVER") or "imap.gmail.com",
                    int(os.getenv("GMAIL_IMAP_PORT", "993")),
                    gmail_email,
                    gmail_password,
                    use_ssl=True,
                    verify_ssl=True,
                )
            )
        )
    else:
        print(Colors.colorize("\n⚠  Gmail credentials not configured", Colors.YELLOW))


def _test_outlook_account(results: list) -> None:
    """Run connection diagnostics for Outlook if enabled."""
    if os.getenv("OUTLOOK_ENABLED", "").lower() != "true":
        return

    outlook_email = os.getenv("OUTLOOK_EMAIL", "")
    outlook_password = os.getenv("OUTLOOK_APP_PASSWORD", "")

    if outlook_email and outlook_password:
        results.append(
            test_connection(
                ConnectionConfig(
                    "Outlook",
                    os.getenv("OUTLOOK_IMAP_SERVER") or "outlook.office365.com",
                    int(os.getenv("OUTLOOK_IMAP_PORT", "993")),
                    outlook_email,
                    outlook_password,
                    use_ssl=True,
                    verify_ssl=True,
                )
            )
        )
    else:
        print(Colors.colorize("\n⚠  Outlook credentials not configured", Colors.YELLOW))


def _test_proton_account(results: list) -> None:
    """Run connection diagnostics for Proton Mail Bridge if enabled."""
    if os.getenv("PROTON_ENABLED", "").lower() != "true":
        return

    proton_email = os.getenv("PROTON_EMAIL", "")
    proton_password = os.getenv("PROTON_APP_PASSWORD", "")
    proton_server = os.getenv("PROTON_IMAP_SERVER") or "127.0.0.1"
    proton_port = int(os.getenv("PROTON_IMAP_PORT", "1143"))

    if proton_email and proton_password:
        verify = os.getenv("PROTON_VERIFY_SSL", "true").lower() != "false"
        results.append(
            test_connection(
                ConnectionConfig(
                    "Proton Mail Bridge (as configured)",
                    proton_server,
                    proton_port,
                    proton_email,
                    proton_password,
                    use_ssl=True,
                    verify_ssl=verify,
                )
            )
        )
        print("\n--- Trying Proton without SSL (STARTTLS) ---")
        results.append(
            test_connection(
                ConnectionConfig(
                    "Proton Mail Bridge (STARTTLS fallback)",
                    proton_server,
                    proton_port,
                    proton_email,
                    proton_password,
                    use_ssl=False,
                    verify_ssl=False,
                )
            )
        )
    else:
        print(Colors.colorize("\n⚠  Proton credentials not configured", Colors.YELLOW))


def main():
    # Load environment
    load_dotenv(".env")

    print("Email Security Pipeline - Connection Diagnostics")
    print(f"Python SSL version: {ssl.OPENSSL_VERSION}")
    print(f"TLS support: {ssl.HAS_TLSv1_2}, {ssl.HAS_TLSv1_3}")

    results = []
    _test_gmail_account(results)
    _test_outlook_account(results)
    _test_proton_account(results)

    print("\n" + "=" * 60)
    if not results:
        print(
            Colors.colorize(
                "⚠  No email accounts were tested. Please ensure at least one provider is enabled and configured in .env",
                Colors.YELLOW,
            )
        )
    print("Diagnostics complete")
    print("=" * 60)

    sys.exit(0 if (results and all(results)) else 1)


if __name__ == "__main__":
    main()
