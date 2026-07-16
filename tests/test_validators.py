import unittest
from unittest.mock import MagicMock, Mock

from src.utils.config import AlertConfig, Config, EmailAccountConfig
from src.utils.validators import check_default_credentials

SCENARIOS = [
    ("no_defaults_clean", True, "test-user@example.com", "mock_pass_val", False, None, False, None, []),
    (
        "default_email",
        True,
        "your-email@gmail.com",
        "mock_pass_val",
        False,
        None,
        False,
        None,
        ["Gmail account enabled but uses default email: your-email@gmail.com"],
    ),
    (
        "default_password",
        True,
        "test-user@example.com",
        "your-app-password-here",
        False,
        None,
        False,
        None,
        ["Gmail account enabled but uses default password"],
    ),
    (
        "disabled_account_ignored",
        False,
        "your-email@gmail.com",
        "your-app-password-here",
        False,
        None,
        False,
        None,
        [],
    ),
    (
        "default_webhook",
        None,
        None,
        None,
        True,
        "https://your-webhook-url.com/alerts",
        False,
        None,
        ["Webhook alerts enabled but uses default URL"],
    ),
    (
        "default_slack",
        None,
        None,
        None,
        False,
        None,
        True,
        "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        ["Slack alerts enabled but uses default Webhook URL"],
    ),
    (
        "multiple_errors",
        True,
        "your-email@gmail.com",
        "your-app-password-here",
        True,
        "https://your-webhook-url.com/alerts",
        True,
        "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        [
            "Gmail account enabled but uses default email: your-email@gmail.com",
            "Gmail account enabled but uses default password",
            "Webhook alerts enabled but uses default URL",
            "Slack alerts enabled but uses default Webhook URL",
        ],
    ),
]


class TestValidators(unittest.TestCase):
    def setUp(self):
        # Create a mock config
        self.config = MagicMock(spec=Config)
        self.config.email_accounts = []
        self.config.alerts = MagicMock(spec=AlertConfig)
        self.config.alerts.webhook_enabled = False
        self.config.alerts.slack_enabled = False

    def test_check_default_credentials(self):
        for (
            name,
            acc_enabled,
            acc_email,
            acc_pw,
            wh_enabled,
            wh_url,
            sl_enabled,
            sl_url,
            expected,
        ) in SCENARIOS:
            with self.subTest(scenario=name):
                self.config.email_accounts = (
                    [
                        Mock(
                            spec=EmailAccountConfig,
                            enabled=acc_enabled,
                            email=acc_email,
                            app_password=acc_pw,
                            provider="gmail",
                        )
                    ]
                    if acc_email
                    else []
                )
                self.config.alerts.webhook_enabled = wh_enabled
                self.config.alerts.webhook_url = wh_url
                self.config.alerts.slack_enabled = sl_enabled
                self.config.alerts.slack_webhook = sl_url

                errors = check_default_credentials(self.config)
                self.assertEqual(errors, expected)


if __name__ == "__main__":
    unittest.main()
