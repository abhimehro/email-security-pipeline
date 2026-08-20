#!/usr/bin/env python3
"""
Configuration Test Script
Tests the email security pipeline configuration and basic functionality.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional

from src.utils.colors import Colors

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
            print(
                Colors.colorize(
                    f"✖ ERROR: Configuration file '{config_file}' not found",
                    Colors.RED,
                )
            )
            return False

        print(
            Colors.colorize(f"✔ Found configuration file: {config_file}", Colors.GREEN)
        )

        # Load configuration
        config = Config(config_file)
        print(Colors.colorize("✔ Configuration object created", Colors.GREEN))

        # Validate configuration
        try:
            config.validate()
            print(Colors.colorize("✔ Configuration validation passed", Colors.GREEN))
        except Exception as e:
            print(
                Colors.colorize(f"✖ Configuration validation failed: {e}", Colors.RED)
            )
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

        print(Colors.colorize("\n✔ Configuration loading test PASSED", Colors.GREEN))
        return True

    except Exception as e:
        print(Colors.colorize(f"✖ ERROR: {e}", Colors.RED))
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
            print(Colors.colorize(f"✔ {module_name}", Colors.GREEN))
        except Exception as e:
            print(Colors.colorize(f"✖ {module_name}: {e}", Colors.RED))
            all_passed = False

    if all_passed:
        print(Colors.colorize("\n✔ Module imports test PASSED", Colors.GREEN))
    else:
        print(Colors.colorize("\n✖ Module imports test FAILED", Colors.RED))

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
        print(Colors.colorize("✔ SpamAnalyzer initialized", Colors.GREEN))
        print(f"    SpamAnalyzer config: {spam_analyzer}")
        # Use spam_analyzer to avoid unused variable warning
        if hasattr(spam_analyzer, "status"):
            print(f"    SpamAnalyzer status: {spam_analyzer.status()}")
        elif hasattr(spam_analyzer, "is_enabled"):
            print(f"    SpamAnalyzer enabled: {spam_analyzer.is_enabled()}")
        else:
            print(f"    SpamAnalyzer object: {spam_analyzer}")

        nlp_analyzer = NLPThreatAnalyzer(config.analysis)
        print(Colors.colorize("✔ NLPThreatAnalyzer initialized", Colors.GREEN))
        # Use nlp_analyzer to avoid unused variable warning
        if hasattr(nlp_analyzer, "status"):
            print(f"    NLPThreatAnalyzer status: {nlp_analyzer.status()}")
        elif hasattr(nlp_analyzer, "is_enabled"):
            print(f"    NLPThreatAnalyzer enabled: {nlp_analyzer.is_enabled()}")
        else:
            print(f"    NLPThreatAnalyzer object: {nlp_analyzer}")

        media_analyzer = MediaAuthenticityAnalyzer(config.analysis)
        print(Colors.colorize("✔ MediaAuthenticityAnalyzer initialized", Colors.GREEN))
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
        print(Colors.colorize("✔ AlertSystem initialized", Colors.GREEN))
        # Use alert_system to avoid unused variable warning
        if hasattr(alert_system, "status"):
            print(f"    AlertSystem status: {alert_system.status()}")
        elif hasattr(alert_system, "is_enabled"):
            print(f"    AlertSystem enabled: {alert_system.is_enabled()}")
        else:
            print(f"    AlertSystem object: {alert_system}")

        print(Colors.colorize("\n✔ Analyzer initialization test PASSED", Colors.GREEN))
        return True

    except Exception as e:
        print(Colors.colorize(f"✖ ERROR: {e}", Colors.RED))
        import traceback

        traceback.print_exc()
        return False


def _validate_config_for_test(config) -> bool:
    """Validate config for the connection test, printing any errors."""
    from src.utils.config import ConfigurationError

    try:
        config.validate()
        return True
    except ConfigurationError as e:
        print(Colors.colorize("✖ Configuration validation failed:", Colors.RED))
        for error in e.args[0]:
            print(f"  - {error}")
        return False


def _print_client_folders(client, email: str) -> None:
    """List folders for a connected client, printing results or errors."""
    try:
        folders = client.list_folders()
        print(f"  - {email}: Found {len(folders)} folder(s)")
        if folders:
            print(
                f"    Folders: {', '.join(folders[:5])}{'...' if len(folders) > 5 else ''}"
            )
    except Exception as e:
        print(f"  - {email}: Error listing folders - {e}")


def test_imap_connections(test_connections=True):
    """Test IMAP connections (optional)."""
    print("\n" + "=" * 60)
    print("Test 4: IMAP Connections")
    print("=" * 60)

    if not test_connections:
        print(
            Colors.colorize(
                "⏭️  Skipping IMAP connection tests (use --test-connections to enable)",
                Colors.YELLOW,
            )
        )
        return True

    try:
        from src.modules.email_ingestion import EmailIngestionManager
        from src.utils.config import Config

        config = Config(".env")
        if not _validate_config_for_test(config):
            return False

        if not config.email_accounts:
            print(
                Colors.colorize(
                    "⚠️  No email accounts configured, skipping connection test",
                    Colors.YELLOW,
                )
            )
            return True

        print(f"Testing connections for {len(config.email_accounts)} account(s)...")

        ingestion_manager = EmailIngestionManager(
            config.email_accounts, config.system.rate_limit_delay
        )

        # Try to initialize clients
        if ingestion_manager.initialize_clients():
            print(
                f"✔ Successfully connected to {len(ingestion_manager.clients)} account(s)"
            )

            # List folders for each account
            for email, client in ingestion_manager.clients.items():
                _print_client_folders(client, email)

            # Clean up
            ingestion_manager.close_all_connections()
            print(Colors.colorize("\n✔ IMAP connections test PASSED", Colors.GREEN))
            return True
        else:
            print(
                Colors.colorize(
                    "✖ Failed to connect to any email accounts", Colors.RED
                )
            )
            print("   Please check your credentials and IMAP settings")
            return False

    except Exception as e:
        print(Colors.colorize(f"✖ ERROR: {e}", Colors.RED))
        import traceback

        traceback.print_exc()
        return False


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
                print(Colors.colorize(f"✔ '{input_value}' → {result}", Colors.GREEN))
            else:
                print(
                    Colors.colorize(
                        f"✖ '{input_value}' → {result} (expected {expected})",
                        Colors.RED,
                    )
                )
                all_passed = False

        if all_passed:
            print(Colors.colorize("\n✔ Folder parsing test PASSED", Colors.GREEN))
        else:
            print(Colors.colorize("\n✖ Folder parsing test FAILED", Colors.RED))

        return all_passed

    except Exception as e:
        print(Colors.colorize(f"✖ ERROR: {e}", Colors.RED))
        import traceback

        traceback.print_exc()
        return False


def _get_first_enabled_account(config) -> Optional[str]:
    """Get the first enabled email account from config."""
    for acc in config.email_accounts:
        if acc.enabled:
            return acc.email
    return None


def _check_script_exists(script_path: str) -> bool:
    """Check if the diagnostics script exists."""
    return Path(script_path).exists()


def _run_diagnostics_script(
    script_path: str, email: str
) -> subprocess.CompletedProcess:
    """Run the diagnostics script and return the result."""
    from src.utils.security_validators import is_safe_email

    if not is_safe_email(email):
        raise ValueError(f"Invalid or unsafe email address for diagnostics: {email}")

    return subprocess.run(  # nosec B603: email is validated by is_safe_email(); script_path is a repository-controlled constant, not user input.
        [sys.executable, script_path, email],
        capture_output=True,
        text=True,
        check=False,
    )


def _validate_script_result(result: subprocess.CompletedProcess) -> bool:
    """Validate the script execution result."""
    if result.returncode != 0:
        print(
            Colors.colorize(
                f"✖ Script failed with return code {result.returncode}", Colors.RED
            )
        )
        print(f"   Stderr: {result.stderr}")
        return False
    return True


def _validate_json_output(output) -> bool:
    """Validate the JSON output from the script."""
    required_keys = [
        "server_reachable",
        "port_open",
        "ssl_valid",
        "credentials_valid",
    ]

    if not all(key in output for key in required_keys):
        print(
            Colors.colorize(
                f"✖ JSON output missing required keys. Found: {list(output.keys())}",
                Colors.RED,
            )
        )
        return False

    print(Colors.colorize("✔ JSON output contains all required keys", Colors.GREEN))

    if "host_resolved" not in output.get("server_reachable", {}):
        print(Colors.colorize("✖ Nested structure is incorrect", Colors.RED))
        return False

    print(Colors.colorize("✔ Nested structure appears correct", Colors.GREEN))
    return True


def test_diagnostics_script():
    """Test the connectivity diagnostics script."""
    print("\n" + "=" * 60)
    print("Test 6: Connectivity Diagnostics Script")
    print("=" * 60)

    try:
        from src.utils.config import Config

        config = Config(".env")

        if not config.email_accounts:
            print(
                Colors.colorize(
                    "⚠️ No email accounts configured, skipping diagnostics script test",
                    Colors.YELLOW,
                )
            )
            return True

        test_account_email = _get_first_enabled_account(config)
        if not test_account_email:
            print(
                "⚠️ No enabled email accounts found, skipping diagnostics script test"
            )
            return True

        print(f"Testing diagnostics for: {test_account_email}")

        script_path = "./scripts/diagnose_connectivity.py"
        if not _check_script_exists(script_path):
            print(
                Colors.colorize(
                    f"✖ ERROR: Diagnostics script not found at {script_path}",
                    Colors.RED,
                )
            )
            return False

        result = _run_diagnostics_script(script_path, test_account_email)
        if not _validate_script_result(result):
            return False

        try:
            output = json.loads(result.stdout)
            print(Colors.colorize("✔ Script produced valid JSON output", Colors.GREEN))
            if _validate_json_output(output):
                print(
                    Colors.colorize("\n✔ Diagnostics script test PASSED", Colors.GREEN)
                )
                return True
            return False

        except json.JSONDecodeError:
            print(Colors.colorize("✖ Script output is not valid JSON", Colors.RED))
            print(f"   Stdout: {result.stdout}")
            return False

    except Exception as e:
        print(Colors.colorize(f"✖ ERROR: {e}", Colors.RED))
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
        status = (
            Colors.colorize("✔ PASS", Colors.GREEN)
            if result
            else Colors.colorize("✖ FAIL", Colors.RED)
        )
        print(f"{status} - {test_name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print(
            Colors.colorize(
                "\n🎉 All tests PASSED! Your configuration is ready to use.",
                Colors.GREEN,
            )
        )
        return 0
    else:
        print(
            Colors.colorize(
                "\n⚠️  Some tests FAILED. Please review the errors above.",
                Colors.YELLOW,
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
