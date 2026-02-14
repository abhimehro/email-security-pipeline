
import unittest
from unittest.mock import MagicMock, patch
import requests
from src.modules.alert_system import AlertSystem
from src.utils.config import AlertConfig

class TestErrorRedaction(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AlertConfig)
        self.config.console = False
        self.config.webhook_enabled = True
        self.config.slack_enabled = True
        self.config.threat_low = 0
        self.alert_system = AlertSystem(self.config)

    def test_sanitize_error_message_slack(self):
        """Test redaction of Slack webhook URLs in error messages"""
        secret_url = "https://hooks.slack.com/services/T123/B456/SUPER_SECRET_TOKEN"
        error_msg = f"Max retries exceeded with url: {secret_url}"
        error = requests.exceptions.ConnectionError(error_msg)

        sanitized = self.alert_system._sanitize_error_message(error)

        self.assertIn("[REDACTED]", sanitized)
        self.assertNotIn("SUPER_SECRET_TOKEN", sanitized)
        self.assertIn("T123", sanitized) # Team ID is usually not sensitive
        self.assertIn("B456", sanitized) # Bot ID is usually not sensitive

    def test_sanitize_error_message_discord(self):
        """Test redaction of Discord webhook URLs in error messages"""
        secret_url = "https://discord.com/api/webhooks/123456789/SUPER_SECRET_TOKEN"
        error_msg = f"Max retries exceeded with url: {secret_url}"
        error = requests.exceptions.ConnectionError(error_msg)

        sanitized = self.alert_system._sanitize_error_message(error)

        self.assertIn("[REDACTED]", sanitized)
        self.assertNotIn("SUPER_SECRET_TOKEN", sanitized)
        self.assertIn("123456789", sanitized)

    def test_sanitize_error_message_query_params(self):
        """Test redaction of sensitive query params in error messages"""
        secret_url = "https://example.com/api?token=SECRET&user=admin"
        error_msg = f"Error connecting to {secret_url}"
        error = Exception(error_msg)

        sanitized = self.alert_system._sanitize_error_message(error)

        # urlencode encodes brackets as %5B and %5D
        self.assertIn("token=%5BREDACTED%5D", sanitized)
        self.assertNotIn("SECRET", sanitized)
        self.assertIn("user=admin", sanitized)

    def test_sanitize_error_message_multiple_urls(self):
        """Test redaction of multiple URLs in one message"""
        msg = "Failed to connect to https://hooks.slack.com/services/T1/B1/TOKEN1 and https://hooks.slack.com/services/T2/B2/TOKEN2"
        error = Exception(msg)

        sanitized = self.alert_system._sanitize_error_message(error)

        self.assertIn("TOKEN1", msg) # Original has tokens
        self.assertNotIn("TOKEN1", sanitized)
        self.assertNotIn("TOKEN2", sanitized)
        self.assertIn("[REDACTED]", sanitized)

if __name__ == '__main__':
    unittest.main()
