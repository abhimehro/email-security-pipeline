import unittest
from unittest.mock import MagicMock
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import IMAPClient, EmailAccountConfig

class TestIngestionOptimization(unittest.TestCase):
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

        raw_email = msg.as_string().encode('utf-8')

        email_data = self.client.parse_email("2", raw_email, "INBOX")

        self.assertEqual(len(email_data.body_text), 11)
        self.assertEqual(email_data.body_text, "Part1:12345")

        # Should create a warning because we attempted to add more but couldn't
        # Wait, original logic:
        # if len < max: append
        # if len > max: truncate & warn
        # If len == max after first part, second part: if len < max -> False.
        # So it skips appending second part. Does it warn?
        # Original logic:
        # if len(body_text) < self.max_body_size: ...
        # So if it is exactly max, it skips the block. No warning generated for the skip?
        # Let's check original logic carefully.

        # Logic:
        # if len(body_text) < self.max_body_size:
        #    body_text += text_part
        #    if len(body_text) > self.max_body_size:
        #         truncate & warn

        # If part1 fills it exactly. len=11. max=11.
        # Loop part 2.
        # if 11 < 11: False.
        # So it skips part 2 silently.

        # My new logic should replicate this behavior (or improve it).
        # Improving it means maybe warning that content was skipped?
        # But "Bolt's Philosophy: Preserve existing functionality exactly".
        # So I should expect NO warning if the first part fills it exactly?
        # Actually, if part 1 was > 11, it would be truncated and warned.
        # If part 1 == 11. No warning.
        # Part 2 skipped silently.

        # Let's see if warning is logged.
        found_warning = False
        for call in self.client.logger.warning.call_args_list:
            args, _ = call
            if "Body text truncated" in args[0]:
                found_warning = True
                break

        # Based on my analysis of original code, it should NOT warn if exact match occurs before next part.
        self.assertFalse(found_warning, "Truncation warning logged unexpectedly for exact fit")

if __name__ == '__main__':
    unittest.main()
