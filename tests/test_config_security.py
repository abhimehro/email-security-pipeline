import os
import secrets
import subprocess  # nosec B404
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import test_config
from src.utils.config import (
    AlertConfig,
    AnalysisConfig,
    Config,
    ConfigurationError,
    EmailAccountConfig,
)
from src.utils.security_validators import is_safe_email

# Deterministic-feeling secret for tests; generated so it is not a hardcoded password.
_TEST_APP_SECRET = secrets.token_hex(16)


class TestConfigSecurity(unittest.TestCase):
    def test_alert_config_repr_security(self):
        """Test that AlertConfig __repr__ does not leak webhooks."""
        secret_webhook = "https://hooks.slack.com/services/T000/B000/SECRET"
        secret_url = "https://example.com?token=SECRET"

        config = AlertConfig(
            console=True,
            webhook_enabled=True,
            webhook_url=secret_url,
            slack_enabled=True,
            slack_webhook=secret_webhook,
            threat_low=30.0,
            threat_medium=60.0,
            threat_high=80.0,
        )

        repr_str = str(config)
        self.assertNotIn(secret_webhook, repr_str, "Slack webhook leaked in __repr__")
        self.assertNotIn(secret_url, repr_str, "Webhook URL leaked in __repr__")
        self.assertNotIn("slack_webhook", repr_str, "Field name should be hidden")

    def test_email_account_config_repr_security(self):
        """Test that EmailAccountConfig __repr__ does not leak app_password."""
        secret_password = "SUPER_SECRET_PASSWORD_123"
        config = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password=secret_password,
            folders=["INBOX"],
            provider="test",
            use_ssl=True,
        )

        repr_str = str(config)
        self.assertNotIn(secret_password, repr_str, "Password leaked in __repr__")
        self.assertNotIn(
            "app_password",
            repr_str,
            "app_password field name shouldn't be in __repr__ if excluded",
        )

    def test_analysis_config_repr_security(self):
        """Test that AnalysisConfig __repr__ does not leak deepfake_api_key."""
        secret_key = "SECRET_API_KEY_XYZ"
        config = AnalysisConfig(
            spam_threshold=0.5,
            spam_check_headers=True,
            spam_check_urls=True,
            nlp_model="test",
            nlp_model_revision="test-rev",
            nlp_threshold=0.5,
            nlp_batch_size=1,
            check_social_engineering=True,
            check_urgency_markers=True,
            check_authority_impersonation=True,
            check_media_attachments=True,
            deepfake_detection_enabled=True,
            media_analysis_timeout=60,
            deepfake_provider="test",
            deepfake_api_key=secret_key,
            deepfake_api_url="http://test",
            deepfake_model_path=None,
        )

        repr_str = str(config)
        self.assertNotIn(secret_key, repr_str, "API Key leaked in __repr__")
        self.assertNotIn(
            "deepfake_api_key",
            repr_str,
            "deepfake_api_key field name shouldn't be in __repr__ if excluded",
        )


class TestEmailValidation(unittest.TestCase):
    """SECURITY STORY: Email addresses from configuration must be validated
    before being passed to subprocesses or IMAP clients. These tests guard
    against command-injection vectors and argparse option-injection via
    malformed addresses."""

    def test_is_safe_email_accepts_valid_addresses(self):
        valid_emails = [
            "test@example.com",
            "user.name+tag@sub.domain.co.uk",
            "user_name@example.com",
            "user-name@example.com",
            "user%name@example.com",
            "a@b.co",
        ]
        for email in valid_emails:
            self.assertTrue(is_safe_email(email), f"Expected valid: {email}")

    def test_is_safe_email_rejects_shell_metacharacters(self):
        unsafe_emails = [
            "user;cmd@example.com",
            "user|cmd@example.com",
            "user&cmd@example.com",
            "user`cmd@example.com",
            "user$(cmd)@example.com",
            "user$var@example.com",
            "user<foo@example.com",
            "user>foo@example.com",
            "user\\foo@example.com",
            "user foo@example.com",
            "user\tfoo@example.com",
            "user\ncmd@example.com",
        ]
        for email in unsafe_emails:
            self.assertFalse(is_safe_email(email), f"Expected unsafe: {email}")

    def test_is_safe_email_rejects_structural_issues(self):
        malformed = [
            "invalid-email",
            "user@",
            "@domain.com",
            "user@domain",
            "user..name@domain.com",
            ".user@example.com",
            "user.@example.com",
            "-user@example.com",
            "user@-example.com",
            "user@example-.com",
            "user@.example.com",
            "user@example.com.",
            "user@example..com",
            "user@example.c",
            "",
            "a" * 250 + "@example.com",  # exceeds 254 char max
        ]
        for email in malformed:
            self.assertFalse(is_safe_email(email), f"Expected malformed: {email}")

    def _validate_email_env(self, email: str) -> str | None:
        """Build a minimal Gmail config with the given email and validate it.

        Returns the ConfigurationError message if validation fails, or None
        if validation succeeds.
        """
        env = {
            "GMAIL_ENABLED": "true",
            "GMAIL_EMAIL": email,
            "GMAIL_APP_PASSWORD": _TEST_APP_SECRET,
            "GMAIL_IMAP_SERVER": "imap.gmail.com",
            "GMAIL_IMAP_PORT": "993",
            "GMAIL_FOLDERS": "INBOX",
            "GMAIL_USE_SSL": "true",
        }
        # Use clear=True so ambient environment variables cannot affect these tests.
        with patch.dict(os.environ, env, clear=True):
            config = Config(env_file="nonexistent.env")
            try:
                config.validate()
                return None
            except ConfigurationError as exc:
                return str(exc)

    def test_config_validate_rejects_malformed_email(self):
        error = self._validate_email_env("bad;email@example.com")
        self.assertIsNotNone(error)
        self.assertIn("Invalid email format", error)

    def test_config_validate_accepts_valid_email(self):
        self.assertIsNone(self._validate_email_env("valid@gmail.com"))

    def test_run_diagnostics_script_rejects_unsafe_email(self):
        with self.assertRaises(ValueError):
            test_config._run_diagnostics_script(
                "scripts/diagnose_connectivity.py", "bad;email@example.com"
            )

    def test_run_diagnostics_script_passes_valid_email(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.MagicMock()
            test_config._run_diagnostics_script(
                "scripts/diagnose_connectivity.py", "valid@example.com"
            )
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            self.assertEqual(args[0], sys.executable)
            self.assertEqual(args[1], "scripts/diagnose_connectivity.py")
            self.assertEqual(args[2], "valid@example.com")


class TestDiagnoseConnectivityValidation(unittest.TestCase):
    def test_rejects_unsafe_email_argument(self):
        repo_root = Path(__file__).resolve().parents[1]
        script = repo_root / "scripts" / "diagnose_connectivity.py"
        result = subprocess.run(  # nosec B603
            [sys.executable, str(script), "bad;email@example.com"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Invalid or unsafe email address", result.stderr)


if __name__ == "__main__":
    unittest.main()
