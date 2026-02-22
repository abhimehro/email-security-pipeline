import unittest
import email
from email.message import Message
from unittest.mock import MagicMock
from src.modules.email_parser import EmailParser
from src.utils.config import EmailAccountConfig

class TestMissingFilename(unittest.TestCase):
    def setUp(self):
        # Create a mock config
        self.config = MagicMock(spec=EmailAccountConfig)
        self.config.provider = "test"
        self.config.email = "test@example.com"

        # Instantiate parser with mock config
        self.parser = EmailParser(
            self.config,
            max_body_size=1024*1024,
            max_attachment_bytes=25*1024*1024,
            max_total_attachment_bytes=100*1024*1024,
            max_attachment_count=10
        )

    def test_extract_attachment_missing_filename(self):
        """Test that _extract_attachment handles missing filename"""
        # Create a message part representing an attachment without filename
        msg = Message()
        msg.add_header('Content-Type', 'text/plain')
        msg.add_header('Content-Disposition', 'attachment') # No filename parameter
        msg.set_payload('test content')

        # Call _extract_attachment
        result = self.parser._extract_attachment(msg, [], 0, "1")

        # Verify result
        self.assertIsNotNone(result, "Attachment should not be None")
        self.assertTrue(result['filename'].startswith('unnamed_attachment'), f"Filename should start with unnamed_attachment, got {result['filename']}")
        # mimetypes.guess_extension('text/plain') returns .txt on most systems
        self.assertTrue(result['filename'].endswith('.txt'), f"Filename should end with .txt, got {result['filename']}")

if __name__ == '__main__':
    unittest.main()
