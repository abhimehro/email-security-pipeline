"""
Unit tests for src/utils/config.py.
Validates loading, parsing, normalization, and validation rules for Config.
"""

import os
from unittest.mock import patch

import pytest

from src.utils.config import (
    AlertConfig,
    AnalysisConfig,
    Config,
    ConfigurationError,
    EmailAccountConfig,
    SystemConfig,
)


class TestEmailAccountConfig:
    def test_hostname_normalization(self):
        account = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="  IMAP.Gmail.COM  ",
            imap_port=993,
            app_password="test-password-123",
            folders=["INBOX"],
            provider="gmail",
            use_ssl=True,
            smtp_server="  SMTP.Gmail.COM  ",
        )
        assert account.imap_server == "imap.gmail.com"
        assert account.smtp_server == "smtp.gmail.com"

    def test_smtp_server_none_normalization(self):
        account = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="test-password-123",
            folders=["INBOX"],
            provider="generic",
            use_ssl=True,
            smtp_server=None,
        )
        assert account.smtp_server is None


class TestConfigHelperMethods:
    @pytest.mark.parametrize(
        "raw_value,expected",
        [
            ("", ["INBOX"]),
            ("INBOX", ["INBOX"]),
            ("INBOX,Sent,Archive", ["INBOX", "Sent", "Archive"]),
            ("INBOX\nSent\nArchive", ["INBOX", "Sent", "Archive"]),
            ("  INBOX  ,  Sent  \n  Archive  ", ["INBOX", "Sent", "Archive"]),
            (",,  ,", ["INBOX"]),
        ],
    )
    def test_parse_folders(self, raw_value, expected):
        assert Config._parse_folders(raw_value) == expected

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("true", True),
            ("TRUE", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("0", False),
            ("no", False),
            ("off", False),
            ("random", False),
        ],
    )
    def test_get_bool(self, monkeypatch, value, expected):
        monkeypatch.setenv("TEST_FLAG", value)
        assert Config._get_bool("TEST_FLAG") is expected

    def test_get_bool_default(self, monkeypatch):
        monkeypatch.delenv("MISSING_FLAG", raising=False)
        assert Config._get_bool("MISSING_FLAG", default=True) is True
        assert Config._get_bool("MISSING_FLAG", default=False) is False

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://hooks.slack.com/services/test", True),
            ("http://hooks.slack.com/services/test", False),
            ("https://", False),
            ("not-a-url", False),
            ("", False),
        ],
    )
    def test_is_https_url(self, url, expected):
        assert Config._is_https_url(url) is expected


class TestConfigLoadingAndDefaults:
    def test_load_all_providers(self, monkeypatch):
        env = {
            "GMAIL_ENABLED": "true",
            "GMAIL_EMAIL": "alice@gmail.com",
            "GMAIL_APP_PASSWORD": "mock-gmail-password",
            "OUTLOOK_ENABLED": "true",
            "OUTLOOK_EMAIL": "bob@outlook.com",
            "OUTLOOK_APP_PASSWORD": "mock-outlook-password",
            "PROTON_ENABLED": "true",
            "PROTON_EMAIL": "charlie@proton.me",
            "PROTON_APP_PASSWORD": "mock-proton-password",
        }
        with patch.dict(os.environ, env, clear=True):
            config = Config(env_file="nonexistent.env")
            assert len(config.email_accounts) == 3
            providers = [acc.provider for acc in config.email_accounts]
            assert providers == ["gmail", "outlook", "proton"]

    def test_system_and_analysis_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = Config(env_file="nonexistent.env")
            assert config.analysis.spam_threshold == 5.0
            assert config.analysis.spam_check_headers is True
            assert config.analysis.spam_check_urls is True
            assert config.analysis.nlp_threshold == 0.7
            assert config.analysis.nlp_batch_size == 8
            assert config.analysis.deepfake_provider == "simulator"
            assert config.system.log_level == "INFO"
            assert config.system.log_format == "text"
            assert config.system.log_rotation_size_mb == 10
            assert config.system.log_rotation_keep_files == 5
            assert config.system.check_interval == 300
            assert config.system.max_emails_per_batch == 50
            assert config.system.rate_limit_delay == 1
            assert config.system.max_attachment_size_mb == 25
            assert config.system.max_body_size_kb == 1024


class TestConfigValidation:
    def _create_valid_config(self) -> Config:
        with patch.dict(
            os.environ,
            {
                "GMAIL_ENABLED": "true",
                "GMAIL_EMAIL": "user@gmail.com",
                "GMAIL_APP_PASSWORD": "mock-app-password",
            },
            clear=True,
        ):
            return Config(env_file="nonexistent.env")

    def _assert_invalid_config(self, config: Config, expected_error: str) -> None:
        """Assert that config.validate() raises ConfigurationError containing expected_error."""
        with pytest.raises(ConfigurationError) as exc_info:
            config.validate()
        assert any(expected_error in err for err in exc_info.value.args[0])

    def test_valid_config_passes(self):
        config = self._create_valid_config()
        assert config.validate() is True

    def test_validate_no_accounts_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            config = Config(env_file="nonexistent.env")
            self._assert_invalid_config(config, "No email accounts configured")

    def test_validate_missing_credentials(self):
        config = self._create_valid_config()
        config.email_accounts[0].app_password = ""
        self._assert_invalid_config(config, "Missing credentials for gmail account")

    def test_validate_invalid_email_format(self):
        config = self._create_valid_config()
        config.email_accounts[0].email = "invalid-email"
        self._assert_invalid_config(config, "Invalid email format for gmail account")

    def test_validate_no_folders(self):
        config = self._create_valid_config()
        config.email_accounts[0].folders = []
        self._assert_invalid_config(config, "No folders configured for gmail account")

    def test_validate_invalid_imap_port(self):
        config = self._create_valid_config()
        config.email_accounts[0].imap_port = 0
        self._assert_invalid_config(config, "Invalid IMAP port for gmail account")

    def test_validate_disallowed_mail_server(self):
        config = self._create_valid_config()
        config.email_accounts[0].imap_server = "malicious.evil.com"
        self._assert_invalid_config(config, "IMAP server for gmail account")

    def test_validate_disallowed_smtp_server(self):
        config = self._create_valid_config()
        config.email_accounts[0].smtp_server = "malicious.evil.com"
        self._assert_invalid_config(config, "SMTP server for gmail account")

    def test_validate_webhook_enabled_without_url(self):
        config = self._create_valid_config()
        config.alerts.webhook_enabled = True
        config.alerts.webhook_url = ""
        self._assert_invalid_config(config, "Webhook enabled but no URL provided")

    def test_validate_webhook_url_must_be_https(self):
        config = self._create_valid_config()
        config.alerts.webhook_enabled = True
        config.alerts.webhook_url = "http://example.com/webhook"
        self._assert_invalid_config(config, "Webhook URL must use HTTPS")

    def test_validate_webhook_url_ssrf_failure(self):
        config = self._create_valid_config()
        config.alerts.webhook_enabled = True
        config.alerts.webhook_url = "https://127.0.0.1/webhook"
        self._assert_invalid_config(config, "Webhook URL SSRF check failed")

    def test_validate_slack_webhook_without_url(self):
        config = self._create_valid_config()
        config.alerts.slack_enabled = True
        config.alerts.slack_webhook = ""
        self._assert_invalid_config(
            config, "Slack alerts enabled but no webhook URL provided"
        )

    def test_validate_slack_webhook_must_be_https(self):
        config = self._create_valid_config()
        config.alerts.slack_enabled = True
        config.alerts.slack_webhook = "http://hooks.slack.com/services/test"
        self._assert_invalid_config(config, "Slack webhook URL must use HTTPS")

    def test_validate_slack_webhook_invalid_host(self):
        config = self._create_valid_config()
        config.alerts.slack_enabled = True
        config.alerts.slack_webhook = "https://not-slack.com/services/test"
        self._assert_invalid_config(
            config, "Slack webhook URL must be a valid Slack hooks endpoint"
        )

    def test_validate_threat_threshold_order(self):
        config = self._create_valid_config()
        config.alerts.threat_low = 80.0
        config.alerts.threat_medium = 50.0
        config.alerts.threat_high = 20.0
        self._assert_invalid_config(
            config, "Threat thresholds must satisfy LOW < MEDIUM < HIGH"
        )

    def test_validate_system_max_attachment_size(self):
        config = self._create_valid_config()
        config.system.max_attachment_size_mb = 0
        self._assert_invalid_config(
            config, "MAX_ATTACHMENT_SIZE_MB must be greater than zero"
        )

    def test_validate_system_log_level(self):
        config = self._create_valid_config()
        config.system.log_level = "NONEXISTENT_LEVEL"
        self._assert_invalid_config(config, "Invalid log level: NONEXISTENT_LEVEL")

    def test_validate_system_log_format(self):
        config = self._create_valid_config()
        config.system.log_format = "yaml"
        self._assert_invalid_config(config, "Invalid log format: yaml")

    def test_validate_system_log_rotation_size(self):
        config = self._create_valid_config()
        config.system.log_rotation_size_mb = 0
        self._assert_invalid_config(
            config, "LOG_ROTATION_SIZE_MB must be greater than zero"
        )

    def test_validate_system_log_rotation_keep_files(self):
        config = self._create_valid_config()
        config.system.log_rotation_keep_files = 0
        self._assert_invalid_config(
            config, "LOG_ROTATION_KEEP_FILES must be greater than zero"
        )
