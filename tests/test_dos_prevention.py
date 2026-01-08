
import unittest
from email.message import EmailMessage
from unittest.mock import MagicMock
from src.modules.email_ingestion import IMAPClient, EmailAccountConfig
from src.utils.config import Config

class TestDoSPrevention(unittest.TestCase):
    def setUp(self):
        self.account_config = EmailAccountConfig(
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
        self.client = IMAPClient(self.account_config)
        # Set limit to 1KB for testing
        self.client.max_body_size = 1024

    def test_body_truncation(self):
        # Create a large email body
        large_body = "A" * 10000 # 10KB

        msg = EmailMessage()
        msg.set_content(large_body)
        msg["Subject"] = "Test Subject"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"

        raw_email = msg.as_bytes()

        # Parse it
        email_data = self.client.parse_email("123", raw_email, "INBOX")

        # Verify truncation
        self.assertIsNotNone(email_data)
        self.assertEqual(len(email_data.body_text), 1024)
        self.assertTrue(email_data.body_text.startswith("A" * 1024))

    def test_html_body_truncation(self):
        # Create large HTML body
        large_html = "<html><body>" + ("B" * 10000) + "</body></html>"

        msg = EmailMessage()
        msg.add_alternative(large_html, subtype='html')
        msg["Subject"] = "Test HTML"

        raw_email = msg.as_bytes()

        email_data = self.client.parse_email("124", raw_email, "INBOX")

        self.assertIsNotNone(email_data)
        self.assertEqual(len(email_data.body_html), 1024)

if __name__ == '__main__':
    unittest.main()
