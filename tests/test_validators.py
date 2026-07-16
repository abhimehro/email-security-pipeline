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

    def test_check_default_credentials(self):
        scenarios = [
            {
                "name": "no_defaults_clean",
                "email_accounts": [
                    Mock(
                        spec=EmailAccountConfig,
                        enabled=True,
                        email="real@test.com",
                        app_password="real-password",
                        provider="gmail",
                    )
                ],
                "webhook_enabled": False,
                "webhook_url": None,
                "slack_enabled": False,
                "slack_webhook": None,
                "expected_errors": []
            },
            {
                "name": "default_email",
                "email_accounts": [
                    Mock(
                        spec=EmailAccountConfig,
                        enabled=True,
                        email="your-email@gmail.com",
                        app_password="real-password",
                        provider="gmail",
                    )
                ],
                "webhook_enabled": False,
                "webhook_url": None,
                "slack_enabled": False,
                "slack_webhook": None,
                "expected_errors": ["Gmail account enabled but uses default email: your-email@gmail.com"]
            },
            {
                "name": "default_password",
                "email_accounts": [
                    Mock(
                        spec=EmailAccountConfig,
                        enabled=True,
                        email="real@test.com",
                        app_password="your-app-password-here",
                        provider="gmail",
                    )
                ],
                "webhook_enabled": False,
                "webhook_url": None,
                "slack_enabled": False,
                "slack_webhook": None,
                "expected_errors": ["Gmail account enabled but uses default password"]
            },
            {
                "name": "disabled_account_ignored",
                "email_accounts": [
                    Mock(
                        spec=EmailAccountConfig,
                        enabled=False,
                        email="your-email@gmail.com",
                        app_password="your-app-password-here",
                        provider="gmail",
                    )
                ],
                "webhook_enabled": False,
                "webhook_url": None,
                "slack_enabled": False,
                "slack_webhook": None,
                "expected_errors": []
            },
            {
                "name": "default_webhook",
                "email_accounts": [],
                "webhook_enabled": True,
                "webhook_url": "https://your-webhook-url.com/alerts",
                "slack_enabled": False,
                "slack_webhook": None,
                "expected_errors": ["Webhook alerts enabled but uses default URL"]
            },
            {
                "name": "default_slack",
                "email_accounts": [],
                "webhook_enabled": False,
                "webhook_url": None,
                "slack_enabled": True,
                "slack_webhook": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
                "expected_errors": ["Slack alerts enabled but uses default Webhook URL"]
            },
            {
                "name": "multiple_errors",
                "email_accounts": [
                    Mock(
                        spec=EmailAccountConfig,
                        enabled=True,
                        email="your-email@gmail.com",
                        app_password="your-app-password-here",
                        provider="gmail",
                    )
                ],
                "webhook_enabled": True,
                "webhook_url": "https://your-webhook-url.com/alerts",
                "slack_enabled": True,
                "slack_webhook": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
                "expected_errors": [
                    "Gmail account enabled but uses default email: your-email@gmail.com",
                    "Gmail account enabled but uses default password",
                    "Webhook alerts enabled but uses default URL",
                    "Slack alerts enabled but uses default Webhook URL"
                ]
            }
        ]

        for scenario in scenarios:
            with self.subTest(scenario=scenario["name"]):
                self.config.email_accounts = scenario["email_accounts"]
                self.config.alerts.webhook_enabled = scenario["webhook_enabled"]
                self.config.alerts.webhook_url = scenario["webhook_url"]
                self.config.alerts.slack_enabled = scenario["slack_enabled"]
                self.config.alerts.slack_webhook = scenario["slack_webhook"]

                errors = check_default_credentials(self.config)

                self.assertEqual(errors, scenario["expected_errors"])

if __name__ == "__main__":
    unittest.main()
