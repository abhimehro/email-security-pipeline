"""
Mail server host validation tests for SSRF prevention.

Validates the unified ALLOWED_MAIL_SERVER_HOSTS allowlist and its integration
into Config.validate() and the standalone connectivity scripts.
"""

import secrets
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root and scripts directory to path for standalone script imports
sys.path.insert(0, str(Path(__file__).parent.parent))
scripts_dir = str(Path(__file__).parent.parent / "scripts")
sys.path.insert(0, scripts_dir)

with patch("dotenv.load_dotenv"):
    import check_mail_connectivity  # type: ignore[import-not-found]

from src.utils.config import Config, ConfigurationError, EmailAccountConfig
from src.utils.security_validators import (
    ALLOWED_MAIL_SERVER_HOSTS,
    validate_mail_server_host,
)

# Dummy credential used in tests. Generated at runtime so no static secret is
# hard-coded in the source file.
DUMMY_VALUE = secrets.token_hex(16)


def _make_email_config(
    imap_server: str = "imap.gmail.com",
    smtp_server: str | None = None,
    app_secret: str = DUMMY_VALUE,
) -> EmailAccountConfig:
    """Return a minimal EmailAccountConfig for tests."""
    return EmailAccountConfig(
        True,
        "test@example.com",
        imap_server,
        993,
        app_secret,
        ["INBOX"],
        "test",
        True,
        smtp_server,
    )


class TestValidateMailServerHost(unittest.TestCase):
    """Unit tests for the unified mail-server host validator."""

    def test_allowed_hosts_pass(self):
        """All allowed hosts (including case/whitespace variants) must validate."""
        for host in ALLOWED_MAIL_SERVER_HOSTS:
            with self.subTest(host=host):
                # Should not raise
                validate_mail_server_host(host)
                validate_mail_server_host(host.upper())
                validate_mail_server_host(f"  {host}  ")
                validate_mail_server_host(f"{host}.")

    def test_disallowed_hosts_rejected(self):
        """Known attacker-friendly hosts must be rejected."""
        disallowed_hosts = [
            "169.254.169.254",
            "10.0.0.5",
            "internal.evil.com",
            "imap.evil.com",
            "smtp.evil.com",
            "localhost.localdomain",
        ]
        for host in disallowed_hosts:
            with self.subTest(host=host):
                with self.assertRaises(ValueError) as cm:
                    validate_mail_server_host(host)
                self.assertIn("not in the allowed server list", str(cm.exception))

    def test_normalization_bypasses_blocked(self):
        """Case, whitespace, and trailing-dot tricks must not bypass the allowlist."""
        with self.assertRaises(ValueError) as cm:
            validate_mail_server_host("  EVIL.COM. ")
        self.assertIn("evil.com", str(cm.exception))

    def test_empty_host_rejected(self):
        """Empty hosts must be rejected cleanly."""
        with self.assertRaises(ValueError) as cm:
            validate_mail_server_host("")
        self.assertIn("host is empty", str(cm.exception))

    def test_allowed_host_normalized(self):
        """Allowed hosts with normalization must pass."""
        validate_mail_server_host(" IMAP.GMAIL.COM. ")
        validate_mail_server_host("SMTP.GMAIL.COM")
        validate_mail_server_host("  LocalHost  ")


class TestConfigMailServerValidation(unittest.TestCase):
    """Tests for Config.validate() mail server host enforcement."""

    def _run_config_host_test(
        self,
        imap_server: str,
        smtp_server: str,
        expected_valid: bool,
        app_secret: str | None = None,
    ) -> None:
        """Run Config.validate() with the given hosts and check the outcome."""
        if app_secret is None:
            app_secret = DUMMY_VALUE

        account = _make_email_config(
            imap_server=imap_server,
            smtp_server=smtp_server,
            app_secret=app_secret,
        )

        with patch("src.utils.config.load_dotenv"):
            with patch("src.utils.config.os.getenv") as mock_getenv:
                mock_getenv.side_effect = lambda key, default=None: default
                with patch.object(
                    Config, "_load_email_accounts", return_value=[account]
                ):
                    config = Config()
                    if expected_valid:
                        self.assertTrue(config.validate())
                        return

                    with self.assertRaises(ConfigurationError) as cm:
                        config.validate()

                    errors = cm.exception.args[0]
                    error_blob = "\n".join(str(e) for e in errors)
                    self.assertTrue(
                        any("not in the allowed server list" in e for e in errors),
                        f"Expected allowlist error, got: {errors}",
                    )
                    self.assertNotIn(
                        app_secret,
                        error_blob,
                        "Validation error must not leak the app secret",
                    )

    def test_config_validates_allowed_imap_smtp(self):
        """Valid allowed IMAP/SMTP hosts pass Config.validate()."""
        self._run_config_host_test(
            "imap.gmail.com", "smtp.gmail.com", expected_valid=True
        )

    def test_config_rejects_disallowed_imap(self):
        """Disallowed IMAP host is caught without leaking credentials."""
        self._run_config_host_test(
            "169.254.169.254",
            "smtp.gmail.com",
            expected_valid=False,
            app_secret=secrets.token_hex(16),
        )

    def test_config_rejects_disallowed_smtp(self):
        """Disallowed SMTP host is caught by Config.validate()."""
        self._run_config_host_test(
            "imap.gmail.com",
            "internal.evil.com",
            expected_valid=False,
        )


class TestCheckMailConnectivityValidation(unittest.TestCase):
    """Tests that scripts/check_mail_connectivity.py validates hosts before connecting."""

    def _make_config(
        self,
        host: str = "169.254.169.254",
        app_secret: str | None = None,
    ) -> check_mail_connectivity.ConnectionConfig:
        if app_secret is None:
            app_secret = DUMMY_VALUE
        return check_mail_connectivity.ConnectionConfig(
            "Test",
            host,
            993,
            True,
            "test@example.com",
            app_secret,
            None,
        )

    @patch("check_mail_connectivity.imaplib.IMAP4_SSL")
    def test_check_imap_rejects_disallowed_host(self, mock_imap_ssl):
        """check_imap must reject a disallowed host and never open a socket."""
        app_secret = secrets.token_hex(16)
        config = self._make_config(host="10.0.0.5", app_secret=app_secret)

        result = check_mail_connectivity.check_imap(config)

        self.assertFalse(result["success"])
        self.assertIn("not in the allowed server list", result["error"])
        self.assertNotIn(app_secret, result["error"])
        mock_imap_ssl.assert_not_called()

    @patch("check_mail_connectivity.imaplib.IMAP4_SSL")
    def test_check_imap_allows_allowed_host(self, mock_imap_ssl):
        """check_imap with an allowed host should attempt a connection."""
        mock_imap = MagicMock()
        mock_imap_ssl.return_value = mock_imap

        config = self._make_config(host="imap.gmail.com")
        result = check_mail_connectivity.check_imap(config)

        self.assertTrue(result["success"])
        mock_imap_ssl.assert_called_once()

    @patch("check_mail_connectivity.smtplib.SMTP_SSL")
    def test_check_smtp_rejects_disallowed_host(self, mock_smtp_ssl):
        """check_smtp must reject a disallowed host and never open a socket."""
        app_secret = secrets.token_hex(16)
        config = self._make_config(host="internal.evil.com", app_secret=app_secret)

        result = check_mail_connectivity.check_smtp(config)

        self.assertFalse(result["success"])
        self.assertIn("not in the allowed server list", result["error"])
        self.assertNotIn(app_secret, result["error"])
        mock_smtp_ssl.assert_not_called()

    @patch("check_mail_connectivity.smtplib.SMTP_SSL")
    def test_check_smtp_allows_allowed_host(self, mock_smtp_ssl):
        """check_smtp with an allowed host should attempt a connection."""
        mock_smtp = MagicMock()
        mock_smtp_ssl.return_value = mock_smtp

        config = self._make_config(host="smtp.gmail.com")
        result = check_mail_connectivity.check_smtp(config)

        self.assertTrue(result["success"])
        mock_smtp_ssl.assert_called_once()


class TestEmailAccountConfigSMTPField(unittest.TestCase):
    """Sanity checks for the new smtp_server field on EmailAccountConfig."""

    def test_smtp_server_field_default(self):
        """EmailAccountConfig still works without an explicit smtp_server."""
        config = _make_email_config()
        self.assertIsNone(config.smtp_server)

    def test_smtp_server_field_set(self):
        """EmailAccountConfig can carry an smtp_server value."""
        config = _make_email_config(smtp_server="smtp.gmail.com")
        self.assertEqual(config.smtp_server, "smtp.gmail.com")


if __name__ == "__main__":
    unittest.main()
