
import unittest
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from src.modules.email_ingestion import IMAPClient, EmailAccountConfig, MAX_MIME_PARTS

class TestMimeBombLimit(unittest.TestCase):
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
        # Increase body size limit to ensure we don't hit that first
        self.client.max_body_size = 10 * 1024 * 1024

    def test_excessive_mime_parts(self):
        # Create a multipart email with many parts
        msg = MIMEMultipart()
        msg["Subject"] = "MIME Bomb Test"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"

        # Add parts exceeding the limit
        # The first part yielded by walk() is the multipart container itself.
        # So we can process MAX_MIME_PARTS - 1 attachments before hitting the limit.
        num_attachments = MAX_MIME_PARTS + 50

        for i in range(num_attachments):
            part = MIMEText(f"Part {i}\n")
            msg.attach(part)

        raw_email = msg.as_bytes()

        # Parse it
        email_data = self.client.parse_email("123", raw_email, "INBOX")

        self.assertIsNotNone(email_data)

        # Verify that we got the first parts
        self.assertIn("Part 0", email_data.body_text)

        # The limit is inclusive of the container.
        # So we expect parts 0 to (MAX_MIME_PARTS - 2) to be present.
        # e.g. if MAX=100: 1 container + 99 attachments = 100 parts processed.
        # Attachments 0 to 98 are processed. Attachment 99 is the 101st part (skipped).

        last_allowed_idx = MAX_MIME_PARTS - 2
        self.assertIn(f"Part {last_allowed_idx}", email_data.body_text)

        # Verify that parts beyond the limit are truncated
        first_skipped_idx = MAX_MIME_PARTS - 1
        self.assertNotIn(f"Part {first_skipped_idx}", email_data.body_text)
        self.assertNotIn(f"Part {num_attachments - 1}", email_data.body_text)

if __name__ == '__main__':
    unittest.main()
