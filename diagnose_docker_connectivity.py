#!/usr/bin/env python3
"""
Diagnostic script to test email connectivity from within Docker container context.
This helps identify whether issues are credential-based or network/SSL-based.
"""

import imaplib
import os
import ssl
import sys

from dotenv import load_dotenv


def test_connection(label, host, port, email, password, use_ssl=True, verify_ssl=True):
    """Test IMAP connection with detailed diagnostics."""
    print(f"\n{'='*60}")
    print(f"Testing: {label}")
    print(f"Host: {host}:{port}")
    print(f"Email: {email}")
    print(f"SSL: {use_ssl}, Verify: {verify_ssl}")
    print(f"{'='*60}")

    try:
        if use_ssl:
            if verify_ssl:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()
                print("⚠️  SSL verification DISABLED")

            print(f"Connecting to {host}:{port} with SSL...")
            imap = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=30)
        else:
            print(f"Connecting to {host}:{port} without SSL...")
            imap = imaplib.IMAP4(host, port, timeout=30)
            print("Upgrading to TLS...")
            if verify_ssl:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()
            imap.starttls(ssl_context=context)

        print("✓ Connection established")
        print(f"Logging in as {email}...")

        imap.login(email, password)
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


def main():
    # Load environment
    load_dotenv(".env")

    print("Email Security Pipeline - Connection Diagnostics")
    print(f"Python SSL version: {ssl.OPENSSL_VERSION}")
    print(f"TLS support: {ssl.HAS_TLSv1_2}, {ssl.HAS_TLSv1_3}")

    # Test Gmail
    if os.getenv("GMAIL_ENABLED", "").lower() == "true":
        gmail_email = os.getenv("GMAIL_EMAIL", "")
        gmail_password = os.getenv("GMAIL_APP_PASSWORD", "")

        if gmail_email and gmail_password:
            test_connection(
                "Gmail",
                os.getenv("GMAIL_IMAP_SERVER", "imap.gmail.com"),
                int(os.getenv("GMAIL_IMAP_PORT", "993")),
                gmail_email,
                gmail_password,
                use_ssl=True,
                verify_ssl=True,
            )
        else:
            print("\n⚠️  Gmail credentials not configured")

    # Test Proton with SSL verification
    if os.getenv("PROTON_ENABLED", "").lower() == "true":
        proton_email = os.getenv("PROTON_EMAIL", "")
        proton_password = os.getenv("PROTON_APP_PASSWORD", "")
        proton_server = os.getenv("PROTON_IMAP_SERVER", "127.0.0.1")
        proton_port = int(os.getenv("PROTON_IMAP_PORT", "1143"))

        if proton_email and proton_password:
            # First try with verification disabled (as configured)
            verify = os.getenv("PROTON_VERIFY_SSL", "true").lower() != "false"
            test_connection(
                "Proton Mail Bridge (as configured)",
                proton_server,
                proton_port,
                proton_email,
                proton_password,
                use_ssl=True,
                verify_ssl=verify,
            )

            # Also try without SSL entirely (STARTTLS fallback)
            print("\n--- Trying Proton without SSL (STARTTLS) ---")
            test_connection(
                "Proton Mail Bridge (STARTTLS fallback)",
                proton_server,
                proton_port,
                proton_email,
                proton_password,
                use_ssl=False,
                verify_ssl=False,
            )
        else:
            print("\n⚠️  Proton credentials not configured")

    print("\n" + "=" * 60)
    print("Diagnostics complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
