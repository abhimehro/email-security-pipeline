#!/usr/bin/env python3
"""
Configuration Test Script
Tests the email security pipeline configuration and basic functionality.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


def test_config_loading():
    """Test that configuration loads correctly."""
    print("=" * 60)
    print("Test 1: Configuration Loading")
    print("=" * 60)

    try:
        from src.utils.config import Config

        config_file = ".env"
        if not Path(config_file).exists():
            print(f"❌ ERROR: Configuration file '{config_file}' not found")
            return False

        print(f"✓ Found configuration file: {config_file}")

        # Load configuration
        config = Config(config_file)
        print("✓ Configuration object created")

        # Validate configuration
        try:
            config.validate()
            print("✓ Configuration validation passed")
        except Exception as e:
            print(f"❌ Configuration validation failed: {e}")
            return False

        # Check email accounts
        print(f"\n  Email accounts configured: {len(config.email_accounts)}")
        for account in config.email_accounts:
            print(f"    - {account.provider.upper()}: {account.email}")
            print(f"      Folders: {', '.join(account.folders)}")

        # Check analysis configuration
        print("\n  Analysis Configuration:")
        print(f"    - Spam threshold: {config.analysis.spam_threshold}")
        print(f"    - NLP threshold: {config.analysis.nlp_threshold}")
        print(
            f"    - Media analysis: {'enabled' if config.analysis.check_media_attachments else 'disabled'}"
        )

        # Check alert configuration
        print("\n  Alert Configuration:")
        print(
            f"    - Console alerts: {'enabled' if config.alerts.console else 'disabled'}"
        )
        print(
            f"    - Webhook alerts: {'enabled' if config.alerts.webhook_enabled else 'disabled'}"
        )
        print(
            f"    - Slack alerts: {'enabled' if config.alerts.slack_enabled else 'disabled'}"
        )
        print(
            f"    - Threat thresholds: LOW={config.alerts.threat_low}, MEDIUM={config.alerts.threat_medium}, HIGH={config.alerts.threat_high}"
        )

        # Check system configuration
        print("\n  System Configuration:")
        print(f"    - Log level: {config.system.log_level}")
        print(f"    - Check interval: {config.system.check_interval}s")
        print(f"    - Max emails per batch: {config.system.max_emails_per_batch}")
        print(f"    - Max attachment size: {config.system.max_attachment_size_mb}MB")

        print("\n✓ Configuration loading test PASSED")
        return True

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_module_imports():
    """Test that all modules can be imported."""
    print("\n" + "=" * 60)
    print("Test 2: Module Imports")
    print("=" * 60)

    modules = [
        "src.utils.config",
        "src.modules.email_ingestion",
        "src.modules.spam_analyzer",
        "src.modules.nlp_analyzer",
        "src.modules.media_analyzer",
        "src.modules.alert_system",
    ]

    all_passed = True
    for module_name in modules:
        try:
            __import__(module_name)
            print(f"✓ {module_name}")
        except Exception as e:
            print(f"❌ {module_name}: {e}")
            all_passed = False

    if all_passed:
        print("\n✓ Module imports test PASSED")
    else:
        print("\n❌ Module imports test FAILED")

    return all_passed


def test_analyzer_initialization():
    """Test that analyzers can be initialized."""
    print("\n" + "=" * 60)
    print("Test 3: Analyzer Initialization")
    print("=" * 60)

    try:
        from src.modules.alert_system import AlertSystem
        from src.modules.media_analyzer import MediaAuthenticityAnalyzer
        from src.modules.nlp_analyzer import NLPThreatAnalyzer
        from src.modules.spam_analyzer import SpamAnalyzer
        from src.utils.config import Config

        config = Config(".env")

        # Initialize analyzers
        spam_analyzer = SpamAnalyzer(config.analysis)
        print("✓ SpamAnalyzer initialized")
        print(f"    SpamAnalyzer config: {spam_analyzer}")
        # Use spam_analyzer to avoid unused variable warning
        if hasattr(spam_analyzer, "status"):
            print(f"    SpamAnalyzer status: {spam_analyzer.status()}")
        elif hasattr(spam_analyzer, "is_enabled"):
            print(f"    SpamAnalyzer enabled: {spam_analyzer.is_enabled()}")
        else:
            print(f"    SpamAnalyzer object: {spam_analyzer}")

        nlp_analyzer = NLPThreatAnalyzer(config.analysis)
        print("✓ NLPThreatAnalyzer initialized")
        # Use nlp_analyzer to avoid unused variable warning
        if hasattr(nlp_analyzer, "status"):
            print(f"    NLPThreatAnalyzer status: {nlp_analyzer.status()}")
        elif hasattr(nlp_analyzer, "is_enabled"):
            print(f"    NLPThreatAnalyzer enabled: {nlp_analyzer.is_enabled()}")
        else:
            print(f"    NLPThreatAnalyzer object: {nlp_analyzer}")

        media_analyzer = MediaAuthenticityAnalyzer(config.analysis)
        print("✓ MediaAuthenticityAnalyzer initialized")
        # Use media_analyzer to avoid unused variable warning
        if hasattr(media_analyzer, "status"):
            print(f"    MediaAuthenticityAnalyzer status: {media_analyzer.status()}")
        elif hasattr(media_analyzer, "is_enabled"):
            print(
                f"    MediaAuthenticityAnalyzer enabled: {media_analyzer.is_enabled()}"
            )
        else:
            print(f"    MediaAuthenticityAnalyzer object: {media_analyzer}")

        alert_system = AlertSystem(config.alerts)
        print("✓ AlertSystem initialized")
        # Use alert_system to avoid unused variable warning
        if hasattr(alert_system, "status"):
            print(f"    AlertSystem status: {alert_system.status()}")
        elif hasattr(alert_system, "is_enabled"):
            print(f"    AlertSystem enabled: {alert_system.is_enabled()}")
        else:
            print(f"    AlertSystem object: {alert_system}")

        print("\n✓ Analyzer initialization test PASSED")
        return True

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_imap_connections(test_connections=True):
    """Test IMAP connections (optional)."""
    print("\n" + "=" * 60)
    print("Test 4: IMAP Connections")
    print("=" * 60)

    if not test_connections:
        print("⏭️  Skipping IMAP connection tests (use --test-connections to enable)")
        return True

    try:
        from src.modules.email_ingestion import EmailIngestionManager
        from src.utils.config import Config

        config = Config(".env")

        if not config.email_accounts:
            print("⚠️  No email accounts configured, skipping connection test")
            return True

        print(f"Testing connections for {len(config.email_accounts)} account(s)...")

        ingestion_manager = EmailIngestionManager(
            config.email_accounts, config.system.rate_limit_delay
        )

        # Try to initialize clients
        if ingestion_manager.initialize_clients():
            print(
                f"✓ Successfully connected to {len(ingestion_manager.clients)} account(s)"
            )

            # List folders for each account
            for email, client in ingestion_manager.clients.items():
                try:
                    folders = client.list_folders()
                    print(f"  - {email}: Found {len(folders)} folder(s)")
                    if folders:
                        print(
                            f"    Folders: {', '.join(folders[:5])}{'...' if len(folders) > 5 else ''}"
                        )
                except Exception as e:
                    print(f"  - {email}: Error listing folders - {e}")

            # Clean up
            ingestion_manager.close_all_connections()
            print("\n✓ IMAP connections test PASSED")
            return True
        else:
            print("❌ Failed to connect to any email accounts")
            print("   Please check your credentials and IMAP settings")
            return False

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


import json
import subprocess
from pathlib import Path


def test_folder_parsing():
    """Test folder parsing functionality."""
    print("\n" + "=" * 60)
    print("Test 5: Folder Parsing")
    print("=" * 60)

    try:
        from src.utils.config import Config

        test_cases = [
            ("INBOX,Sent", ["INBOX", "Sent"]),
            ("INBOX\nSent", ["INBOX", "Sent"]),
            ("INBOX,Spam,Junk", ["INBOX", "Spam", "Junk"]),
            ("INBOX\nSent\nSpam", ["INBOX", "Sent", "Spam"]),
            ("INBOX", ["INBOX"]),
        ]

        all_passed = True
        for input_value, expected in test_cases:
            result = Config._parse_folders(input_value)
            if result == expected:
                print(f"✓ '{input_value}' → {result}")
            else:
                print(f"❌ '{input_value}' → {result} (expected {expected})")
                all_passed = False

        if all_passed:
            print("\n✓ Folder parsing test PASSED")
        else:
            print("\n❌ Folder parsing test FAILED")

        return all_passed

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_diagnostics_script():
    """Test the connectivity diagnostics script."""
    print("\n" + "=" * 60)
    print("Test 6: Connectivity Diagnostics Script")
    print("=" * 60)

    try:
        from src.utils.config import Config

        config = Config(".env")

        if not config.email_accounts:
            print("⚠️ No email accounts configured, skipping diagnostics script test")
            return True

        # Find the first enabled email account to test
        test_account_email = None
        for acc in config.email_accounts:
            if acc.enabled:
                test_account_email = acc.email
                break

        if not test_account_email:
            print(
                "⚠️ No enabled email accounts found, skipping diagnostics script test"
            )
            return True

        print(f"Testing diagnostics for: {test_account_email}")

        script_path = "./scripts/diagnose_connectivity.py"
        if not Path(script_path).exists():
            print(f"❌ ERROR: Diagnostics script not found at {script_path}")
            return False

        result = subprocess.run(
            ["python3", script_path, test_account_email],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            print(f"❌ Script failed with return code {result.returncode}")
            print(f"   Stderr: {result.stderr}")
            return False

        try:
            output = json.loads(result.stdout)
            print("✓ Script produced valid JSON output")

            required_keys = [
                "server_reachable",
                "port_open",
                "ssl_valid",
                "credentials_valid",
            ]
            if all(key in output for key in required_keys):
                print("✓ JSON output contains all required keys")
                # Basic check on a nested value
                if "host_resolved" in output.get("server_reachable", {}):
                    print("✓ Nested structure appears correct")
                    print("\n✓ Diagnostics script test PASSED")
                    return True
                else:
                    print("❌ Nested structure is incorrect")
                    return False
            else:
                print(
                    f"❌ JSON output missing required keys. Found: {list(output.keys())}"
                )
                return False

        except json.JSONDecodeError:
            print("❌ Script output is not valid JSON")
            print(f"   Stdout: {result.stdout}")
            return False

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("Email Security Pipeline - Configuration Test")
    print("=" * 60)
    print()

    # Check for command line arguments
    test_connections = "--test-connections" in sys.argv

    results = []

    # Run tests
    results.append(("Configuration Loading", test_config_loading()))
    results.append(("Module Imports", test_module_imports()))
    results.append(("Analyzer Initialization", test_analyzer_initialization()))
    results.append(("Folder Parsing", test_folder_parsing()))
    results.append(("IMAP Connections", test_imap_connections(test_connections)))
    results.append(("Diagnostics Script", test_diagnostics_script()))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests PASSED! Your configuration is ready to use.")
        return 0
    else:
        print("\n⚠️  Some tests FAILED. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
