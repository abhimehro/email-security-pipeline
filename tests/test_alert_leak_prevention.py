
import unittest
from unittest.mock import MagicMock, patch
import json
from dataclasses import asdict

from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig

class TestAlertSystemLeak(unittest.TestCase):
    def test_webhook_redacts_sensitive_params(self):
        # Setup config
        config = MagicMock(spec=AlertConfig)
        config.console = False
        config.webhook_enabled = True
        config.webhook_url = "https://example.com/webhook"
        config.slack_enabled = False
        config.threat_low = 0  # Alert on everything

        alert_system = AlertSystem(config)

        # Create a report with a sensitive URL
        sensitive_url = "https://evil.com/login?user=admin&password=super_secret_password&token=12345"

        report = ThreatReport(
            email_id="1",
            subject="Test",
            sender="bad@evil.com",
            recipient="me@example.com",
            date="2023-01-01",
            overall_threat_score=50,
            risk_level="high",
            spam_analysis={
                'score': 10,
                'risk_level': 'high',
                'indicators': [],
                'suspicious_urls': [sensitive_url],
                'header_issues': []
            },
            nlp_analysis={},
            media_analysis={},
            recommendations=[],
            timestamp="2023-01-01"
        )

        # Mock requests.post
        with patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200

            alert_system.send_alert(report)

            # Verify call args
            args, kwargs = mock_post.call_args
            json_body = kwargs['json']

            # Check if password leaked
            suspicious_urls = json_body['spam_analysis']['suspicious_urls']

            # The URL should be redacted now
            expected_redacted_url = "https://evil.com/login?user=admin&password=%5BREDACTED%5D&token=%5BREDACTED%5D"
            # Note: urlencode might change order or encoding, so checking containment of redacted parts is safer

            self.assertIn("password=[REDACTED]", suspicious_urls[0].replace('%5B', '[').replace('%5D', ']'))
            self.assertIn("token=[REDACTED]", suspicious_urls[0].replace('%5B', '[').replace('%5D', ']'))
            self.assertNotIn("super_secret_password", suspicious_urls[0])
            self.assertNotIn("12345", suspicious_urls[0])

if __name__ == '__main__':
    unittest.main()
