import unittest
from unittest.mock import MagicMock
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import IMAPClient, EmailAccountConfig
from src.utils.sanitization import sanitize_for_logging

class TestEmailIngestionSecurity(unittest.TestCase):

    def setUp(self):
        self.config = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="pass",
            folders=["INBOX"],
            provider="test",
            use_ssl=True,
            verify_ssl=True
        )
        self.client = IMAPClient(self.config)
        # Mock the logger
        self.client.logger = MagicMock()

    def test_select_folder_log_injection(self):
        """Test that folder names are sanitized when logging"""
        # Simulate a malicious folder name
        malicious_folder = "INBOX\nFake Log Entry\nAnother Fake Entry"

        # We can't test the actual IMAP call without a connection,
        # but we can test that our logger receives sanitized input
        # by mocking the connection response

        self.client.connection = MagicMock()
        self.client.connection.select.return_value = ("OK", [b"1"])

        self.client.select_folder(malicious_folder)

        # Check that logger.debug was called with sanitized folder
        expected_folder = sanitize_for_logging(malicious_folder)

        found_sanitized = False
        for call in self.client.logger.debug.call_args_list:
            args, _ = call
            if expected_folder in args[0]:
                found_sanitized = True
                break

        self.assertTrue(found_sanitized, "Logger did not receive sanitized folder name")

    def test_parse_email_filename_log_injection(self):
        """Test that attachment filename logs are sanitized"""
        email_id = "1"
        folder = "INBOX"

        # Construct a raw email with a malicious filename
        # Use ANSI codes which are cleaner for header testing but still dangerous for logs
        malicious_filename = "virus.exe\x1b[31mMALICIOUS\x1b[0m"

        # Construct raw bytes
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase

        msg = MIMEMultipart()
        msg['Subject'] = 'Test Email'
        msg['From'] = 'attacker@example.com'
        msg['To'] = 'victim@example.com'

        part = MIMEBase('application', 'octet-stream')
        part.set_payload(b'malicious content')
        # Use proper parameter encoding
        part.add_header('Content-Disposition', 'attachment', filename=malicious_filename)
        msg.attach(part)

        raw_email = msg.as_bytes()

        # Force truncation warning to trigger logging of filename
        # Max attachment size = 0 forces truncation if size > 0
        self.client.max_attachment_bytes = 1

        self.client.parse_email(email_id, raw_email, folder)

        # Check warnings
        # Code: self.logger.warning("Attachment %s exceeds max size...", filename, ...)

        expected_filename = sanitize_for_logging(self.client._sanitize_filename(malicious_filename))

        found_sanitized = False
        for call in self.client.logger.warning.call_args_list:
            args, _ = call
            # args[0] is the format string, args[1] should be the filename
            if len(args) > 1:
                logged_filename = args[1]
                if expected_filename == logged_filename:
                    found_sanitized = True
                    break

        self.assertTrue(found_sanitized, "Logger did not receive sanitized filename")

if __name__ == '__main__':
    unittest.main()
