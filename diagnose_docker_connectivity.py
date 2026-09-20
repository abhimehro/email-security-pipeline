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


def _test_provider_account(
    prefix: str, label: str, default_server: str, default_port: int, results: list
) -> None:
    """Run connection diagnostics for a specific provider if enabled."""
    if os.getenv(f"{prefix}_ENABLED", "").lower() != "true":
        return

    email = os.getenv(f"{prefix}_EMAIL", "")
    password = os.getenv(f"{prefix}_APP_PASSWORD", "")
    server = os.getenv(f"{prefix}_IMAP_SERVER") or default_server
    port = int(os.getenv(f"{prefix}_IMAP_PORT", str(default_port)))

    if not email or not password:
        print(Colors.colorize(f"\n⚠  {label} credentials not configured", Colors.YELLOW))
        return

    if prefix == "PROTON":
        verify = os.getenv("PROTON_VERIFY_SSL", "true").lower() != "false"
        results.append(
            test_connection(
                ConnectionConfig(
                    "Proton Mail Bridge (as configured)",
                    server,
                    port,
                    email,
                    password,
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
                    server,
                    port,
                    email,
                    password,
                    use_ssl=False,
                    verify_ssl=False,
                )
            )
        )
    else:
        results.append(
            test_connection(
                ConnectionConfig(
                    label, server, port, email, password, use_ssl=True, verify_ssl=True
                )
            )
        )


def main():
    # Load environment
    load_dotenv(".env")

    print("Email Security Pipeline - Connection Diagnostics")
    print(f"Python SSL version: {ssl.OPENSSL_VERSION}")
    print(f"TLS support: {ssl.HAS_TLSv1_2}, {ssl.HAS_TLSv1_3}")

    results = []
    providers = [
        ("GMAIL", "Gmail", "imap.gmail.com", 993),
        ("OUTLOOK", "Outlook", "outlook.office365.com", 993),
        ("PROTON", "Proton Mail Bridge", "127.0.0.1", 1143),
    ]
    for prefix, label, server, port in providers:
        _test_provider_account(prefix, label, server, port, results)

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
