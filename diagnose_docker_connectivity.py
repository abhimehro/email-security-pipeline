#!/usr/bin/env python3
"""
Diagnostic script to test email connectivity from within Docker container context.
This helps identify whether issues are credential-based or network/SSL-based.
"""

import imaplib
import os
import ssl
from dataclasses import dataclass

from dotenv import load_dotenv


@dataclass
class ConnectionConfig:
    label: str
    host: str
    port: int
    email: str
    password: str
    use_ssl: bool = True
    verify_ssl: bool = True


def _get_ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    """Create SSL context based on verification flag."""
    if verify_ssl:
        return ssl.create_default_context()
    return ssl._create_unverified_context()  # nosec B323


def _connect_imap(config: ConnectionConfig) -> imaplib.IMAP4:
    """Establish and return an IMAP connection based on config."""
    if config.use_ssl:
        if not config.verify_ssl:
            print("⚠️  SSL verification DISABLED")
        context = _get_ssl_context(config.verify_ssl)
        print(f"Connecting to {config.host}:{config.port} with SSL...")
        return imaplib.IMAP4_SSL(
            config.host, config.port, ssl_context=context, timeout=30
        )

    print(f"Connecting to {config.host}:{config.port} without SSL...")
    imap = imaplib.IMAP4(config.host, config.port, timeout=30)
    print("Upgrading to TLS...")
    context = _get_ssl_context(config.verify_ssl)
    imap.starttls(ssl_context=context)
    return imap


def test_connection(config: ConnectionConfig):
    """Test IMAP connection with detailed diagnostics."""
    print(f"\n{'='*60}")
    print(f"Testing: {config.label}")
    print(f"Host: {config.host}:{config.port}")
    print(f"Email: {config.email}")
    print(f"SSL: {config.use_ssl}, Verify: {config.verify_ssl}")
    print(f"{'='*60}")

    try:
        imap = _connect_imap(config)

        print("✓ Connection established")
        print(f"Logging in as {config.email}...")

        imap.login(config.email, config.password)
        print("✅ SUCCESS - Authentication successful!")

        # Try to list folders
        status, folders = imap.list()
        if status == "OK":
            print(f"✓ Found {len(folders)} folders")

        imap.logout()
        return True

    except imaplib.IMAP4.error as e:
        print(f"❌ IMAP Error: {e}")
        return False
    except ssl.SSLError as e:
        print(f"❌ SSL Error: {e}")
        print(f"   Error type: {type(e).__name__}")
        print(f"   Error args: {e.args}")
        return False
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        print(f"   Error type: {type(e).__name__}")
        return False


def _test_gmail():
    """Test Gmail connectivity if enabled."""
    if os.getenv("GMAIL_ENABLED", "").lower() != "true":
        return

    gmail_email = os.getenv("GMAIL_EMAIL", "")
    gmail_password = os.getenv("GMAIL_APP_PASSWORD", "")

    if gmail_email and gmail_password:
        test_connection(
            ConnectionConfig(
                "Gmail",
                os.getenv("GMAIL_IMAP_SERVER", "imap.gmail.com"),
                int(os.getenv("GMAIL_IMAP_PORT", "993")),
                gmail_email,
                gmail_password,
                use_ssl=True,
                verify_ssl=True,
            )
        )
    else:
        print("\n⚠️  Gmail credentials not configured")


def _test_proton():
    """Test Proton connectivity if enabled."""
    if os.getenv("PROTON_ENABLED", "").lower() != "true":
        return

    proton_email = os.getenv("PROTON_EMAIL", "")
    proton_password = os.getenv("PROTON_APP_PASSWORD", "")
    proton_server = os.getenv("PROTON_IMAP_SERVER", "127.0.0.1")
    proton_port = int(os.getenv("PROTON_IMAP_PORT", "1143"))

    if proton_email and proton_password:
        # First try with verification disabled (as configured)
        verify = os.getenv("PROTON_VERIFY_SSL", "true").lower() != "false"
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

        # Also try without SSL entirely (STARTTLS fallback)
        print("\n--- Trying Proton without SSL (STARTTLS) ---")
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
    else:
        print("\n⚠️  Proton credentials not configured")


def main():
    # Load environment
    load_dotenv(".env")

    print("Email Security Pipeline - Connection Diagnostics")
    print(f"Python SSL version: {ssl.OPENSSL_VERSION}")
    print(f"TLS support: {ssl.HAS_TLSv1_2}, {ssl.HAS_TLSv1_3}")

    # Test Gmail
    _test_gmail()

    # Test Proton with SSL verification
    _test_proton()

    print("\n" + "=" * 60)
    print("Diagnostics complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
