"""Tests for email ingestion optimization and multipart body parsing."""
import unittest
from unittest.mock import MagicMock
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import IMAPClient, EmailAccountConfig


class TestIngestionOptimization(unittest.TestCase):
    """Test suite for optimized email body parsing and truncation."""
    def setUp(self):
        self.config = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="test_password_not_real",
            folders=["INBOX"],
            provider="test",
            use_ssl=True,
            verify_ssl=True
        )
        self.client = IMAPClient(self.config)
        self.client.logger = MagicMock()

    def test_multipart_body_concatenation_and_truncation(self):
        """
        Test that parse_email correctly handles multipart emails and respects
        max_body_size truncation when concatenating multiple parts.
        """
        # Set a small limit: 15 characters
        self.client.max_body_size = 15

        # Create a multipart email
        msg = MIMEMultipart()
        # Part 1: 11 characters
        msg.attach(MIMEText("Part1:12345", "plain"))
        # Part 2: 11 characters (should be truncated to 4)
        msg.attach(MIMEText("Part2:67890", "plain"))

        # Use as_bytes() to better reflect actual IMAP raw email bytes
        raw_email = msg.as_bytes()

        email_data = self.client.parse_email("1", raw_email, "INBOX")

        # Verify body text
        expected_body = "Part1:12345Part"  # 11 + 4 chars
        self.assertEqual(len(email_data.body_text), 15)
        self.assertEqual(email_data.body_text, expected_body)

        # Verify truncation warning was logged
        self.client.logger.warning.assert_called()
        found_warning = False
        for call in self.client.logger.warning.call_args_list:
            args, _ = call
            if "Body text truncated" in args[0]:
                found_warning = True
                break
        self.assertTrue(found_warning, "Truncation warning was not logged")

    def test_multipart_body_exact_limit(self):
        """Test exact limit boundary handling"""
        self.client.max_body_size = 11

        msg = MIMEMultipart()
        msg.attach(MIMEText("Part1:12345", "plain")) # 11 chars
        msg.attach(MIMEText("Part2:67890", "plain")) # 11 chars

        # Use as_bytes() to better reflect actual IMAP raw email bytes
        raw_email = msg.as_bytes()

        email_data = self.client.parse_email("2", raw_email, "INBOX")

        self.assertEqual(len(email_data.body_text), 11)
        self.assertEqual(email_data.body_text, "Part1:12345")

        # When first part exactly fills max_body_size, subsequent parts
        # are skipped without warning (preserving original behavior)
        found_warning = False
        for call in self.client.logger.warning.call_args_list:
            args, _ = call
            if "Body text truncated" in args[0]:
                found_warning = True
                break

        self.assertFalse(
            found_warning,
            "Truncation warning logged unexpectedly for exact fit"
        )


if __name__ == '__main__':
    unittest.main()
