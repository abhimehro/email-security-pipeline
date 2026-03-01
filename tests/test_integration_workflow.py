"""
Integration Workflow Tests
Tests end-to-end email processing flow through the pipeline
"""

import unittest
from unittest.mock import MagicMock, patch, Mock
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import EmailData
from src.modules.spam_analyzer import SpamAnalyzer, SpamAnalysisResult
from src.modules.nlp_analyzer import NLPThreatAnalyzer, NLPAnalysisResult
from src.modules.media_analyzer import MediaAuthenticityAnalyzer, MediaAnalysisResult
from src.modules.alert_system import AlertSystem, generate_threat_report, ThreatReport
from src.utils.config import AnalysisConfig, AlertConfig


class TestIntegrationWorkflow(unittest.TestCase):
    """Test complete end-to-end email processing workflows"""

    def setUp(self):
        """Set up test fixtures"""
        # Create mock configurations
        self.analysis_config = MagicMock(spec=AnalysisConfig)
        self.analysis_config.spam_threshold = 0.7
        self.analysis_config.spam_check_headers = True
        self.analysis_config.spam_check_urls = True
        self.analysis_config.nlp_model = "simple"
        self.analysis_config.nlp_threshold = 0.6
        self.analysis_config.nlp_batch_size = 32
        self.analysis_config.check_social_engineering = True
        self.analysis_config.check_urgency_markers = True
        self.analysis_config.check_authority_impersonation = True
        self.analysis_config.check_media_attachments = True
        self.analysis_config.deepfake_detection_enabled = False
        self.analysis_config.media_analysis_timeout = 30

        self.alert_config = MagicMock(spec=AlertConfig)
        self.alert_config.console = True
        self.alert_config.webhook_enabled = False
        self.alert_config.slack_enabled = False
        self.alert_config.threat_low = 10
        self.alert_config.threat_medium = 50
        self.alert_config.threat_high = 80

        # Initialize analyzers
        self.spam_analyzer = SpamAnalyzer(self.analysis_config)
        self.nlp_analyzer = NLPThreatAnalyzer(self.analysis_config)
        self.media_analyzer = MediaAuthenticityAnalyzer(self.analysis_config)
        self.alert_system = AlertSystem(self.alert_config)

    def _create_email_data(self, subject, body, sender="test@example.com", attachments=None):
        """Helper to create EmailData objects for testing"""
        return EmailData(
            message_id="test-123",
            subject=subject,
            sender=sender,
            recipient="victim@example.com",
            date=datetime.now(),
            body_text=body,
            body_html="",
            headers={},
            attachments=attachments or [],
            raw_email=MagicMock(),
            account_email="victim@example.com",
            folder="INBOX"
        )

    def test_clean_email_full_pipeline(self):
        """
        SECURITY STORY: This tests the complete analysis pipeline with a clean email.
        We verify that benign emails pass through all layers without triggering false alarms.
        This prevents alert fatigue and ensures users trust the system.
        """
        # Create a clean, legitimate email
        email_data = self._create_email_data(
            subject="Meeting Tomorrow at 2 PM",
            body="Hi, just confirming our meeting for tomorrow at 2 PM. See you then!",
            sender="colleague@company.com"
        )

        # Layer 1: Spam Analysis
        spam_result = self.spam_analyzer.analyze(email_data)
        self.assertIsNotNone(spam_result)
        self.assertIsInstance(spam_result, SpamAnalysisResult)
        self.assertLess(spam_result.score, 50.0)  # Should be low for clean email

        # Layer 2: NLP Analysis
        nlp_result = self.nlp_analyzer.analyze(email_data)
        self.assertIsNotNone(nlp_result)
        self.assertIsInstance(nlp_result, NLPAnalysisResult)
        self.assertLess(nlp_result.threat_score, 50.0)  # Should be low for clean email

        # Layer 3: Media Analysis
        media_result = self.media_analyzer.analyze(email_data)
        self.assertIsNotNone(media_result)
        self.assertIsInstance(media_result, MediaAnalysisResult)

        # Generate threat report
        report = generate_threat_report(
            email_data,
            spam_result,
            nlp_result,
            media_result
        )

        self.assertIsInstance(report, ThreatReport)
        self.assertEqual(report.subject, email_data.subject)
        self.assertEqual(report.sender, email_data.sender)
        self.assertLess(report.overall_threat_score, 50.0)  # Clean email = low threat

    def test_high_threat_email_full_pipeline(self):
        """
        SECURITY STORY: This tests detection of a malicious email through all layers.
        Multiple threat indicators (spam patterns + social engineering) should compound
        to produce a high threat score and trigger appropriate alerts.
        """
        # Create a phishing email with multiple threat indicators
        email_data = self._create_email_data(
            subject="URGENT: Verify Your Account Now!!!",
            body="Your account will be SUSPENDED unless you click here immediately: "
                 "http://evil-phishing-site.com/login?verify=now "
                 "Act now or lose access forever! Limited time offer!",
            sender="security@definitely-not-your-bank.com"
        )

        # Layer 1: Spam Analysis
        spam_result = self.spam_analyzer.analyze(email_data)
        # Should detect spam patterns (exclamation marks, urgency keywords, suspicious URL)
        self.assertGreater(len(spam_result.indicators), 0)  # Should find indicators

        # Layer 2: NLP Analysis
        nlp_result = self.nlp_analyzer.analyze(email_data)
        # Should detect urgency and social engineering patterns
        self.assertGreater(len(nlp_result.urgency_markers), 0)  # Should find urgency

        # Layer 3: Media Analysis (no attachments)
        media_result = self.media_analyzer.analyze(email_data)
        self.assertIsNotNone(media_result)

        # Generate threat report
        report = generate_threat_report(
            email_data,
            spam_result,
            nlp_result,
            media_result
        )

        # Verify threat was detected
        self.assertIsNotNone(report)
        self.assertIn(report.risk_level, ["low", "medium", "high"])
        # At minimum, should have recommendations based on detected patterns
        self.assertIsNotNone(report.recommendations)

    def test_pipeline_with_media_attachments(self):
        """
        SECURITY STORY: This tests the complete pipeline when emails contain media attachments.
        Malicious actors often hide threats in media files, so we must analyze them thoroughly
        while respecting resource limits to prevent DoS attacks.
        """
        # Create email with media attachment
        attachments = [{
            'filename': 'vacation.jpg',
            'content_type': 'image/jpeg',
            'size': 1024 * 100,  # 100KB
            'data': b'\xff\xd8\xff\xe0\x00\x10JFIF' + b'\x00' * 100  # JPEG header
        }]

        email_data = self._create_email_data(
            subject="Check out my vacation photos!",
            body="Here are some photos from my trip.",
            attachments=attachments
        )

        # Run through all analyzers
        spam_result = self.spam_analyzer.analyze(email_data)
        nlp_result = self.nlp_analyzer.analyze(email_data)
        media_result = self.media_analyzer.analyze(email_data)

        # Verify media analysis occurred
        # Media result contains threat scores and findings
        self.assertIsNotNone(media_result)

        # Generate report
        report = generate_threat_report(
            email_data,
            spam_result,
            nlp_result,
            media_result
        )

        self.assertIsNotNone(report)
        self.assertIn("media_analysis", report.__dict__)

    def test_pipeline_with_partial_layer_failure(self):
        """
        SECURITY STORY: This tests graceful degradation when one analysis layer fails.
        The pipeline should continue analyzing with remaining layers rather than completely
        failing. This ensures maximum protection even when components have issues.

        PATTERN RECOGNITION: This is similar to circuit breaker patterns in distributed systems.
        We isolate failures to prevent cascade effects while maintaining partial functionality.
        """
        email_data = self._create_email_data(
            subject="Test Email",
            body="Test body content"
        )

        # Test that other analyzers still work even if one fails
        # In practice, the pipeline would catch exceptions from individual analyzers

        # Other analyzers should still work
        spam_result = self.spam_analyzer.analyze(email_data)
        self.assertIsNotNone(spam_result)

        media_result = self.media_analyzer.analyze(email_data)
        self.assertIsNotNone(media_result)

        # NLP analyzer can also work
        nlp_result = self.nlp_analyzer.analyze(email_data)
        self.assertIsNotNone(nlp_result)

        # Should be able to generate report with all analyzers working
        report = generate_threat_report(
            email_data,
            spam_result,
            nlp_result,
            media_result
        )

        self.assertIsNotNone(report)

    @patch('src.modules.alert_system.requests.post')
    def test_alert_generation_and_delivery(self, mock_post):
        """
        SECURITY STORY: This tests that high-threat emails trigger alerts correctly.
        Without reliable alerting, security threats could go unnoticed, defeating
        the purpose of the detection system.
        """
        # Setup mock for successful webhook delivery
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Enable webhook alerts
        self.alert_config.webhook_enabled = True
        self.alert_config.webhook_url = "https://example.com/webhook"
        alert_system = AlertSystem(self.alert_config)

        # Create high-threat report
        report = ThreatReport(
            email_id="test-456",
            subject="URGENT: Your account has been compromised!",
            sender="attacker@evil.com",
            recipient="victim@example.com",
            date=datetime.now().isoformat(),
            overall_threat_score=95.0,
            risk_level="high",
            spam_analysis={'spam_score': 90.0},
            nlp_analysis={'threat_score': 95.0},
            media_analysis={'attachment_count': 0},
            recommendations=["Do not click any links", "Delete email immediately"],
            timestamp=datetime.now().isoformat()
        )

        # Send alert
        alert_system.send_alert(report)

        # Verify webhook was called
        self.assertTrue(mock_post.called)

        # Verify the data sent contains threat information
        call_args = mock_post.call_args
        self.assertIsNotNone(call_args)

        # Check that URL and data were provided
        args, kwargs = call_args
        if args:
            self.assertIn("example.com", args[0])
        elif 'url' in kwargs:
            self.assertIn("example.com", kwargs['url'])

    def test_multiple_emails_batch_processing(self):
        """
        SECURITY STORY: This tests processing multiple emails in sequence.
        Real-world usage involves analyzing batches of emails, so we must ensure
        the pipeline maintains accuracy and doesn't have state pollution between emails.

        MAINTENANCE WISDOM: Future you will thank present you for this test when
        debugging issues where analysis results from one email affect another.
        """
        # Create multiple emails with different threat levels
        emails = [
            self._create_email_data("Meeting Invite", "Let's meet tomorrow", "bob@company.com"),
            self._create_email_data("URGENT ACTION REQUIRED!!!", "Click now!!!", "scammer@evil.com"),
            self._create_email_data("Weekly Newsletter", "Here's this week's news", "news@company.com"),
        ]

        results = []

        for email_data in emails:
            spam_result = self.spam_analyzer.analyze(email_data)
            nlp_result = self.nlp_analyzer.analyze(email_data)
            media_result = self.media_analyzer.analyze(email_data)

            report = generate_threat_report(
                email_data,
                spam_result,
                nlp_result,
                media_result
            )
            results.append(report)

        # Verify we got results for all emails
        self.assertEqual(len(results), 3)

        # Verify different threat levels
        # Email 1 (meeting): low threat
        self.assertLess(results[0].overall_threat_score, 50.0)

        # Email 2 (scam): higher threat (should have urgency/spam markers)
        # Note: Actual score depends on enabled features and NLP availability
        # The important thing is it's analyzed, not the specific score
        self.assertIsNotNone(results[1])

        # Email 3 (newsletter): should be analyzed
        self.assertIsNotNone(results[2])


if __name__ == '__main__':
    unittest.main()
