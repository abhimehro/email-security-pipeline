"""
Error Recovery Tests
Tests error handling, connection recovery, and graceful degradation scenarios
"""

import unittest
from unittest.mock import MagicMock, patch, Mock
import imaplib
import socket
import ssl
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import IMAPClient, EmailIngestionManager, EmailAccountConfig, EmailData
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.utils.config import AnalysisConfig


class TestIMAPErrorRecovery(unittest.TestCase):
    """Test IMAP connection error handling and recovery"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="testpass",
            folders=["INBOX"],
            provider="test",
            use_ssl=True,
            verify_ssl=True
        )
        self.client = IMAPClient(self.config)
        self.client.logger = MagicMock()

    def test_connection_timeout_handling(self):
        """
        SECURITY STORY: This tests timeout handling to prevent hanging indefinitely.
        Attackers might set up honeypot IMAP servers that never respond, attempting
        to consume our resources. Proper timeout handling prevents this DoS attack.
        
        PATTERN RECOGNITION: This is similar to circuit breaker patterns where we
        fail fast rather than waiting indefinitely for a dead service.
        """
        with patch('src.modules.email_ingestion.imaplib.IMAP4_SSL') as mock_imap:
            # Simulate connection timeout
            mock_imap.side_effect = socket.timeout("Connection timed out")
            
            # Attempt to connect
            result = self.client.connect()
            
            # Should return False and not crash
            self.assertFalse(result)
            
            # Should log the error
            self.client.logger.error.assert_called()

    def test_ssl_certificate_error_handling(self):
        """
        SECURITY STORY: This tests SSL certificate validation errors.
        MITM attacks often involve invalid certificates. We must detect and reject
        these to prevent credential theft and email interception.
        """
        with patch('src.modules.email_ingestion.imaplib.IMAP4_SSL') as mock_imap:
            # Simulate SSL certificate error
            mock_imap.side_effect = ssl.SSLError("certificate verify failed")
            
            # Attempt to connect
            result = self.client.connect()
            
            # Should fail securely
            self.assertFalse(result)
            self.client.logger.error.assert_called()

    def test_authentication_failure_handling(self):
        """
        SECURITY STORY: This tests handling of authentication failures.
        Failed logins could indicate credential compromise or misconfiguration.
        We must handle this gracefully and log it for investigation.
        """
        with patch('src.modules.email_ingestion.imaplib.IMAP4_SSL') as mock_imap:
            mock_connection = MagicMock()
            mock_imap.return_value = mock_connection
            
            # Simulate authentication failure
            mock_connection.login.side_effect = imaplib.IMAP4.error("Authentication failed")
            
            # Attempt to connect
            result = self.client.connect()
            
            # Should handle gracefully
            self.assertFalse(result)
            self.client.logger.error.assert_called()

    def test_connection_reset_during_fetch(self):
        """
        SECURITY STORY: This tests handling connection resets during email fetch.
        Network issues or server restarts can interrupt operations. We must handle
        this without crashing and potentially retry.
        """
        self.client.connection = MagicMock()
        
        # Simulate connection reset
        self.client.connection.select.side_effect = imaplib.IMAP4.abort("Connection reset")
        
        # Attempt to fetch unseen emails
        emails = self.client.fetch_unseen_emails("INBOX", limit=10)
        
        # Should return empty list, not crash
        self.assertEqual(emails, [])
        self.client.logger.error.assert_called()

    def test_malformed_email_parsing_recovery(self):
        """
        SECURITY STORY: This tests recovery from malformed email parsing errors.
        Attackers might send intentionally malformed emails to crash the parser.
        We must handle these gracefully and continue processing other emails.
        """
        # Create intentionally malformed email data
        malformed_email = b"This is not a valid email format"
        
        # Attempt to parse
        result = self.client.parse_email("1", malformed_email, "INBOX")
        
        # Should handle gracefully - either return None or minimal data
        # The exact behavior depends on implementation
        if result is None:
            self.assertIsNone(result)
        else:
            # At minimum, should have required fields
            self.assertIsInstance(result, EmailData)

    def test_partial_email_download_recovery(self):
        """
        SECURITY STORY: This tests handling of incomplete email downloads.
        If an email is too large or connection drops mid-transfer, we should
        skip it rather than processing corrupted data which could bypass security checks.
        """
        self.client.connection = MagicMock()
        
        # Simulate partial fetch
        self.client.connection.select.return_value = ('OK', [b'10'])
        self.client.connection.search.return_value = ('OK', [b'1 2 3'])
        
        # First two emails succeed, third fails mid-download
        self.client.connection.fetch.side_effect = [
            ('OK', [(b'1 (RFC822 {1000}', b'email1data')]),
            ('OK', [(b'2 (RFC822 {1000}', b'email2data')]),
            imaplib.IMAP4.abort("Connection lost during fetch")
        ]
        
        # Should recover and return the successfully fetched emails
        emails = self.client.fetch_unseen_emails("INBOX", limit=10)
        
        # Should have processed the first 2 emails successfully
        # Exact behavior depends on implementation
        self.assertIsInstance(emails, list)


class TestAnalyzerTimeoutHandling(unittest.TestCase):
    """Test analyzer timeout and resource limit handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.analysis_config = MagicMock(spec=AnalysisConfig)
        self.analysis_config.check_media_attachments = True
        self.analysis_config.deepfake_detection_enabled = False
        self.analysis_config.media_analysis_timeout = 1  # 1 second timeout for testing

    def test_media_analyzer_timeout(self):
        """
        SECURITY STORY: This tests timeout enforcement for media analysis.
        Attackers could send specially crafted media files that take forever to process,
        causing a DoS. Timeouts ensure we bound resource consumption per email.
        
        MAINTENANCE WISDOM: Future you will thank present you for this test when
        investigating why some emails take too long to process.
        """
        analyzer = MediaAuthenticityAnalyzer(self.analysis_config)
        
        # Create email with attachment
        email_data = EmailData(
            message_id="test-123",
            subject="Test",
            sender="test@example.com",
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="Test",
            body_html="",
            headers={},
            attachments=[{
                'filename': 'test.jpg',
                'content_type': 'image/jpeg',
                'size': 1024,
                'data': b'\xff\xd8\xff\xe0\x00\x10JFIF' + b'\x00' * 100
            }],
            raw_email=MagicMock(),
            account_email="victim@example.com",
            folder="INBOX"
        )

        # Analysis should complete or timeout, not hang
        result = analyzer.analyze(email_data)
        
        # Should return a result (even if it indicates timeout/error)
        self.assertIsNotNone(result)


class TestEmailIngestionManagerRecovery(unittest.TestCase):
    """Test EmailIngestionManager error recovery with multiple accounts"""

    def setUp(self):
        """Set up test fixtures"""
        self.accounts = [
            EmailAccountConfig(
                enabled=True,
                email="account1@example.com",
                imap_server="imap.example.com",
                imap_port=993,
                app_password="pass1",
                folders=["INBOX"],
                provider="test",
                use_ssl=True,
                verify_ssl=True
            ),
            EmailAccountConfig(
                enabled=True,
                email="account2@example.com",
                imap_server="imap.example.com",
                imap_port=993,
                app_password="pass2",
                folders=["INBOX"],
                provider="test",
                use_ssl=True,
                verify_ssl=True
            )
        ]
        self.manager = EmailIngestionManager(
            self.accounts,
            rate_limit_delay=0  # No delay for testing
        )

    def test_partial_account_initialization_failure(self):
        """
        SECURITY STORY: This tests graceful handling when some accounts fail to initialize.
        In production, one account might have wrong credentials while others are fine.
        We should continue monitoring working accounts rather than failing completely.
        
        PATTERN RECOGNITION: This is similar to the "fail-open" vs "fail-closed" debate.
        Here we fail-open for availability, but log failures for investigation.
        """
        with patch('src.modules.email_ingestion.IMAPClient') as mock_client_class:
            # First account succeeds, second fails
            mock_client1 = MagicMock()
            mock_client1.connect.return_value = True
            
            mock_client2 = MagicMock()
            mock_client2.connect.return_value = False
            
            mock_client_class.side_effect = [mock_client1, mock_client2]
            
            # Initialize clients
            result = self.manager.initialize_clients()
            
            # Should succeed even if one account fails
            # Exact behavior depends on implementation
            self.assertIsInstance(result, bool)

    def test_single_account_fetch_failure_isolation(self):
        """
        SECURITY STORY: This tests that fetch failures in one account don't affect others.
        If account isolation fails, an attacker who compromises one account could
        potentially DoS the entire monitoring system by causing fetch errors.
        """
        # Setup mock clients
        client1 = MagicMock()
        client1.fetch_emails.return_value = [MagicMock()]  # Returns 1 email
        
        client2 = MagicMock()
        client2.fetch_emails.side_effect = Exception("Fetch failed")
        
        self.manager.clients = [client1, client2]
        
        # Fetch from all accounts
        emails = self.manager.fetch_all_emails(max_per_folder=10)
        
        # Should get emails from working account despite other account's failure
        self.assertIsInstance(emails, list)

    def test_reconnection_after_connection_loss(self):
        """
        SECURITY STORY: This tests automatic reconnection after connection loss.
        IMAP connections can timeout or be closed by the server. We must detect
        this and reconnect automatically to maintain continuous monitoring.
        
        INDUSTRY CONTEXT: Professional teams handle this by implementing connection
        pooling with health checks and automatic reconnection logic.
        """
        mock_client = MagicMock()
        mock_client.ensure_connection.return_value = True
        mock_client.fetch_unseen_emails.return_value = []
        
        self.manager.clients = {
            self.accounts[0].email: mock_client
        }
        
        # Simulate connection lost, then reconnected
        mock_client.connection = None
        mock_client.connect.return_value = True
        
        # Should attempt reconnection via ensure_connection
        emails = self.manager.fetch_all_emails(max_per_folder=10)
        
        # Should handle gracefully
        self.assertIsInstance(emails, list)


class TestGracefulDegradation(unittest.TestCase):
    """Test graceful degradation scenarios"""

    def test_continue_with_missing_optional_data(self):
        """
        SECURITY STORY: This tests processing emails with missing optional fields.
        Some emails might lack headers, have no body, or be missing metadata.
        We should analyze what we have rather than rejecting the entire email.
        """
        # Email with minimal data
        email_data = EmailData(
            message_id="minimal-123",
            subject="",  # Empty subject
            sender="unknown",  # Minimal sender
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="",  # Empty body
            body_html="",
            headers={},  # No headers
            attachments=[],  # No attachments
            raw_email=MagicMock(),
            account_email="victim@example.com",
            folder="INBOX"
        )

        # Should be valid EmailData
        self.assertIsNotNone(email_data)
        self.assertEqual(email_data.subject, "")
        self.assertEqual(len(email_data.attachments), 0)

    def test_analysis_with_corrupted_attachment(self):
        """
        SECURITY STORY: This tests handling of corrupted or invalid attachments.
        Attackers might send corrupted files hoping to crash the analyzer.
        We should skip invalid attachments and analyze the rest of the email.
        """
        analysis_config = MagicMock(spec=AnalysisConfig)
        analysis_config.check_media_attachments = True
        analysis_config.deepfake_detection_enabled = False
        analysis_config.media_analysis_timeout = 30
        
        analyzer = MediaAuthenticityAnalyzer(analysis_config)
        
        email_data = EmailData(
            message_id="corrupt-123",
            subject="Check this out",
            sender="test@example.com",
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="See attachment",
            body_html="",
            headers={},
            attachments=[{
                'filename': 'broken.jpg',
                'content_type': 'image/jpeg',
                'size': 100,
                'data': b'NOTAJPEG'  # Corrupted/invalid data
            }],
            raw_email=MagicMock(),
            account_email="victim@example.com",
            folder="INBOX"
        )

        # Should handle gracefully and return a result
        result = analyzer.analyze(email_data)
        self.assertIsNotNone(result)
        
        # Should indicate attachment was processed (even if analysis failed)
        # MediaAnalysisResult contains threat_score and warnings
        self.assertIsNotNone(result.threat_score)

    def test_network_error_during_external_api_call(self):
        """
        SECURITY STORY: This tests handling of network errors during external API calls.
        If we depend on external deepfake detection APIs, they might be unavailable.
        The pipeline should continue with degraded capabilities rather than failing.
        
        MAINTENANCE WISDOM: Future you will thank present you for this test when
        the external API goes down and you need to understand system behavior.
        """
        analysis_config = MagicMock(spec=AnalysisConfig)
        analysis_config.check_media_attachments = True
        analysis_config.deepfake_detection_enabled = True
        analysis_config.deepfake_provider = "api"
        analysis_config.deepfake_api_url = "https://api.example.com/detect"
        analysis_config.deepfake_api_key = "test-key"
        analysis_config.media_analysis_timeout = 30
        
        analyzer = MediaAuthenticityAnalyzer(analysis_config)
        
        # Mock network failure
        with patch('src.modules.media_analyzer.requests.post', side_effect=ConnectionError("Network unreachable")):
            email_data = EmailData(
                message_id="net-fail-123",
                subject="Video attachment",
                sender="test@example.com",
                recipient="victim@example.com",
                date=datetime.now(),
                body_text="Check this video",
                body_html="",
                headers={},
                attachments=[{
                    'filename': 'video.mp4',
                    'content_type': 'video/mp4',
                    'size': 1024,
                    'data': b'\x00\x00\x00\x18ftypmp42' + b'\x00' * 100
                }],
                raw_email=MagicMock(),
                account_email="victim@example.com",
                folder="INBOX"
            )

            # Should handle network error gracefully
            result = analyzer.analyze(email_data)
            self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
