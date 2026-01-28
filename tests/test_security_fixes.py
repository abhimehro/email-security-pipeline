import unittest
from unittest.mock import patch, MagicMock
import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Mock cv2 and numpy before importing modules that use them
sys.modules['cv2'] = MagicMock()
sys.modules['numpy'] = MagicMock()

from src.main import EmailSecurityPipeline
from src.modules.email_ingestion import IMAPClient, EmailAccountConfig

class TestSecurityFixes(unittest.TestCase):

    @patch('src.main.RotatingFileHandler')
    @patch('src.main.Config')
    def test_logging_uses_rotating_handler(self, mock_config, mock_rotating_handler):
        """Test that RotatingFileHandler is used instead of FileHandler"""
        # Setup mock config
        mock_config_instance = mock_config.return_value
        mock_config_instance.system.log_file = "logs/test.log"
        mock_config_instance.system.log_level = "INFO"
        mock_config_instance.email_accounts = [] # Avoid initialization of IngestionManager failing hard
        mock_config_instance.analysis = MagicMock()
        mock_config_instance.alerts = MagicMock()

        # Configure the mock handler to have a valid level (int) so logging doesn't crash
        mock_rotating_handler.return_value.level = logging.INFO

        # We need to mock EmailIngestionManager too because it is initialized in __init__
        with patch('src.main.EmailIngestionManager'), \
             patch('src.main.SpamAnalyzer'), \
             patch('src.main.NLPThreatAnalyzer'), \
             patch('src.main.MediaAuthenticityAnalyzer'), \
             patch('src.main.AlertSystem'):

            pipeline = EmailSecurityPipeline(".env")

            # Verify RotatingFileHandler was initialized
            mock_rotating_handler.assert_called_with(
                "logs/test.log",
                maxBytes=10*1024*1024,
                backupCount=5
            )

    def test_imap_connection_timeout(self):
        """Test that IMAP connections use a timeout"""
        config = EmailAccountConfig(
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
        client = IMAPClient(config)
        client.logger = MagicMock()

        # Mock SSL context creation
        with patch.object(client, '_create_secure_ssl_context') as mock_ctx:
            # Test SSL connection
            with patch('imaplib.IMAP4_SSL') as mock_imap_ssl:
                client.connect()

                # Verify timeout was passed
                mock_imap_ssl.assert_called_with(
                    "imap.example.com",
                    993,
                    ssl_context=mock_ctx.return_value,
                    timeout=30
                )

        # Test non-SSL connection
        config.use_ssl = False
        config.imap_port = 143
        client = IMAPClient(config)
        client.logger = MagicMock()

        with patch.object(client, '_create_secure_ssl_context') as mock_ctx:
            with patch('imaplib.IMAP4') as mock_imap:
                client.connect()

                # Verify timeout was passed
                mock_imap.assert_called_with(
                    "imap.example.com",
                    143,
                    timeout=30
                )

if __name__ == '__main__':
    unittest.main()
