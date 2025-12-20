import unittest
from unittest.mock import MagicMock, patch
from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig

class TestAlertSystemSecurity(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AlertConfig)
        self.config.console = True
        self.config.webhook_enabled = False
        self.config.slack_enabled = True
        self.config.slack_webhook = "https://hooks.slack.com/services/test"
        self.config.threat_low = 10
        self.config.threat_medium = 50
        self.config.threat_high = 80

        self.alert_system = AlertSystem(self.config)

    @patch('requests.post')
    def test_slack_injection_prevention(self, mock_post):
        # Create a threat report with malicious content in subject and sender
        report = ThreatReport(
            email_id="123",
            subject="<http://malicious.com|Click Me> & *Bold Lie*",
            sender="Attacker <attacker@evil.com> | <http://evil.com|Evil>",
            recipient="victim@example.com",
            date="2023-01-01",
            overall_threat_score=90.0,
            risk_level="high",
            spam_analysis={},
            nlp_analysis={},
            media_analysis={},
            recommendations=["Delete"],
            timestamp="2023-01-01T12:00:00"
        )

        self.alert_system.send_alert(report)

        # Check that requests.post was called
        self.assertTrue(mock_post.called)

        # Get the payload sent to Slack
        args, kwargs = mock_post.call_args
        payload = kwargs.get('json', {})
        attachments = payload.get('attachments', [])
        self.assertTrue(len(attachments) > 0)
        fields = attachments[0].get('fields', [])

        subject_field = next((f for f in fields if f['title'] == 'Subject'), None)
        sender_field = next((f for f in fields if f['title'] == 'From'), None)

        self.assertIsNotNone(subject_field)
        self.assertIsNotNone(sender_field)

        # Verify that special characters are escaped or removed
        # Slack uses & < > for formatting
        # Expected: & becomes &amp;, < becomes &lt;, > becomes &gt;

        self.assertNotIn("<http://malicious.com|Click Me>", subject_field['value'])
        self.assertNotIn("<http://evil.com|Evil>", sender_field['value'])

        # We expect HTML entity encoding or removal of control chars
        self.assertIn("&lt;", subject_field['value'])
        self.assertIn("&gt;", subject_field['value'])

if __name__ == '__main__':
    unittest.main()
