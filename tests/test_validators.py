import unittest
from unittest.mock import MagicMock, Mock

from src.utils.config import AlertConfig, Config, EmailAccountConfig
from src.utils.validators import check_default_credentials


class TestValidators(unittest.TestCase):
    def setUp(self):
        # Create a mock config
        self.config = MagicMock(spec=Config)
        self.config.email_accounts = []
        self.config.alerts = MagicMock(spec=AlertConfig)
        self.config.alerts.webhook_enabled = False
        self.config.alerts.slack_enabled = False

    def test_no_defaults_clean(self):
        # Setup clean config
        self.config.email_accounts = [
            Mock(
                spec=EmailAccountConfig,
                enabled=True,
                email="real@test.com",
                app_password="real-password",
                provider="gmail",
            )
        ]
        errors = check_default_credentials(self.config)
        self.assertEqual(len(errors), 0)

    def test_default_email(self):
        self.config.email_accounts = [
            Mock(
                spec=EmailAccountConfig,
                enabled=True,
                email="your-email@gmail.com",
                app_password="real-password",
                provider="gmail",
            )
        ]
        errors = check_default_credentials(self.config)

        msg = (
            "Gmail account enabled but uses default email: "
            "your-email@gmail.com"
        )
        self.assertIn(msg, errors)

    def test_default_password(self):
        self.config.email_accounts = [
            Mock(
                spec=EmailAccountConfig,
                enabled=True,
                email="real@test.com",
                app_password="your-app-password-here",
                provider="gmail",
            )
        ]
        errors = check_default_credentials(self.config)
        msg = "Gmail account enabled but uses default password"
        self.assertIn(msg, errors)

    def test_disabled_account_ignored(self):
        self.config.email_accounts = [
            Mock(
                spec=EmailAccountConfig,
                enabled=False,
                email="your-email@gmail.com",
                app_password="your-app-password-here",
                provider="gmail",
            )
        ]
        errors = check_default_credentials(self.config)
        self.assertEqual(len(errors), 0)

    def test_default_webhook(self):
        self.config.alerts.webhook_enabled = True
        self.config.alerts.webhook_url = "https://your-webhook-url.com/alerts"
        errors = check_default_credentials(self.config)
        self.assertIn("Webhook alerts enabled but uses default URL", errors)

    def test_default_slack(self):
        self.config.alerts.slack_enabled = True
        self.config.alerts.slack_webhook = (
            "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        )
        errors = check_default_credentials(self.config)
        msg = "Slack alerts enabled but uses default Webhook URL"
        self.assertIn(msg, errors)

    def test_none_credentials(self):
        self.config.email_accounts = [
            Mock(
                spec=EmailAccountConfig,
                enabled=True,
                email=None,
                app_password=None,
                provider="gmail",
            )
        ]
        self.config.alerts.webhook_enabled = True
        self.config.alerts.webhook_url = None
        self.config.alerts.slack_enabled = True
        self.config.alerts.slack_webhook = None
        errors = check_default_credentials(self.config)
        self.assertEqual(len(errors), 4)

    def test_non_string_credentials(self):
        self.config.email_accounts = [
            Mock(
                spec=EmailAccountConfig,
                enabled=True,
                email=12345,
                app_password={"secret": "password"},
                provider="gmail",
            )
        ]
        self.config.alerts.webhook_enabled = True
        self.config.alerts.webhook_url = ["https://my-webhook.com"]
        self.config.alerts.slack_enabled = True
        self.config.alerts.slack_webhook = 9876.54
        errors = check_default_credentials(self.config)
        self.assertEqual(len(errors), 4)


if __name__ == "__main__":
    unittest.main()
