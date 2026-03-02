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

    @patch('src.modules.alert_system.requests.post')
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
        self.assertGreater(len(attachments), 0)
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
        self.assertIn("&amp;", subject_field['value'])

    @patch('src.modules.alert_system.requests.post')
    def test_slack_sanitization_edge_cases(self, mock_post):
        # Test None, empty string, and only special chars
        test_cases = [
            (None, ""),
            ("", ""),
            ("<>&", "&lt;&gt;&amp;")
        ]

        for input_str, expected in test_cases:
            report = ThreatReport(
                email_id="123",
                subject=input_str if input_str is not None else "", # report.subject usually expects str
                sender="sender",
                recipient="recipient",
                date="2023-01-01",
                overall_threat_score=90.0,
                risk_level="high",
                spam_analysis={},
                nlp_analysis={},
                media_analysis={},
                recommendations=[],
                timestamp="2023-01-01"
            )
            # We are testing the _sanitize_for_slack method which is internal,
            # but we can test via send_alert or by accessing the method if we want unit test specificity.
            # Let's test via send_alert for integration behavior.

            # Note: The AlertSystem handles None in _sanitize_text by returning ""
            # But the ThreatReport dataclass type hint says subject: str.
            # However, if we pass None to dataclass it might accept it at runtime.
            # Let's check _sanitize_for_slack directly to be precise about the edge cases.

            sanitized = self.alert_system._sanitize_for_slack(input_str)
            self.assertEqual(sanitized, expected, f"Failed for input: {input_str}")

    @patch('src.modules.alert_system.is_safe_webhook_url')
    @patch('src.modules.alert_system.requests.post')
    def test_webhook_ssrf_prevention(self, mock_post, mock_is_safe):
        """Test that webhook calls are aborted if unsafe at request time"""
        self.config.webhook_enabled = True
        self.config.webhook_url = "http://169.254.169.254/latest/meta-data/"

        # Mock the safety check to fail, simulating DNS rebinding
        mock_is_safe.return_value = (False, "resolves to link-local")

        report = ThreatReport(
            email_id="123", subject="Test", sender="sender",
            recipient="recipient", date="2023-01-01",
            overall_threat_score=90.0, risk_level="high",
            spam_analysis={}, nlp_analysis={}, media_analysis={},
            recommendations=[], timestamp="2023-01-01"
        )

        system = AlertSystem(self.config)
        system._webhook_alert(report)

        # Verify the post was NOT called due to the SSRF block
        mock_post.assert_not_called()

    @patch('src.modules.alert_system.is_safe_webhook_url')
    @patch('src.modules.alert_system.requests.post')
    def test_slack_ssrf_prevention(self, mock_post, mock_is_safe):
        """Test Slack webhook calls abort if URL is deemed unsafe"""
        self.config.slack_enabled = True
        self.config.slack_webhook = "https://hooks.slack.com/services/test"

        # Mock the safety check to fail
        mock_is_safe.return_value = (False, "resolves to loopback")

        report = ThreatReport(
            email_id="123", subject="Test", sender="sender",
            recipient="recipient", date="2023-01-01",
            overall_threat_score=90.0, risk_level="high",
            spam_analysis={}, nlp_analysis={}, media_analysis={},
            recommendations=[], timestamp="2023-01-01"
        )

        system = AlertSystem(self.config)
        system._slack_alert(report)

        # Verify the post was NOT called
        mock_post.assert_not_called()

    def test_unicode_bidi_spoofing(self):
        """
        Test that BiDi override characters and other invisible control characters
        are removed from sanitized text.
        """
        test_cases = {
            "bidi_spoofing": (f"evil{'\u202e'}exe.pdf", "evilexe.pdf"),
            "zero_width_space": (f"hello{'\u200b'}world", "helloworld"),
            "control_char": (f"text{'\x01'}with_control", "textwith_control"),
        }

        for name, (malicious_text, expected) in test_cases.items():
            with self.subTest(name=name):
                # Test basic sanitization (used for console)
                sanitized = self.alert_system._sanitize_text(malicious_text)
                self.assertEqual(sanitized, expected)

                # Test Slack sanitization (uses _sanitize_text internally)
                slack_safe = self.alert_system._sanitize_for_slack(malicious_text)
                self.assertEqual(slack_safe, expected)

if __name__ == '__main__':
    unittest.main()
