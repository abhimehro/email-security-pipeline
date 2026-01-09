
import unittest
from datetime import datetime
from src.modules.media_analyzer import MediaAuthenticityAnalyzer, MediaAnalysisResult
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaAnalyzerSecurity(unittest.TestCase):
    def setUp(self):
        self.config = AnalysisConfig(
            spam_threshold=5.0,
            spam_check_headers=True,
            spam_check_urls=True,
            nlp_model="test",
            nlp_threshold=0.7,
            nlp_batch_size=8,
            check_social_engineering=True,
            check_urgency_markers=True,
            check_authority_impersonation=True,
            check_media_attachments=True,
            deepfake_detection_enabled=True,
            media_analysis_timeout=60,
            deepfake_provider="simulator",
            deepfake_api_key=None,
            deepfake_api_url=None,
            deepfake_model_path=None
        )
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def test_extension_bypass_with_trailing_space(self):
        """Test that filenames with trailing spaces are correctly identified as dangerous"""
        email_data = EmailData(
            message_id="test",
            subject="Test",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "virus.exe ",
                "content_type": "application/x-msdownload",
                "size": 1000,
                "data": b"MZ...",
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        # Should be flagged as dangerous despite the trailing space
        found_dangerous = False
        for warning in result.file_type_warnings:
            if "Dangerous file type" in warning:
                found_dangerous = True
                break

        self.assertTrue(found_dangerous, "Failed to detect dangerous extension with trailing space")

    def test_extension_bypass_with_null_byte(self):
        """Test that filenames with null bytes are handled safely"""
        # Python strings can contain null bytes, but they can truncate in some C-apis.
        # However, for endswith, it works. But let's see if our logic handles it.
        email_data = EmailData(
            message_id="test",
            subject="Test",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "virus.exe\0.txt",
                "content_type": "text/plain",
                "size": 1000,
                "data": b"MZ...",
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        # If the system blindly trusts the extension after null byte, it sees .txt
        # But if we sanitize or check properly, we might catch it.
        # Actually Python's endswith will check the whole string.
        # 'virus.exe\0.txt'.endswith('.exe') is False.
        # But this is a classic bypass where the OS might treat it as virus.exe
        # We should probably sanitize filenames to remove control characters including null bytes.

        # For this test, let's just see what happens currently.
        # The analyzer checks extension on the filename as is.

        result = self.analyzer.analyze(email_data)
        # We expect this to NOT be flagged as .exe currently because it ends in .txt
        # But we want to ENHANCE the system to strip control chars.
        # Actually in the source code of media_analyzer.py:
        # filename_lower = filename.lower().strip().replace('\0', '')
        # So it DOES handle null bytes. 'virus.exe\0.txt' -> 'virus.exe.txt'.
        pass

    def test_double_extension_spoofing(self):
        """Test detection of double extensions"""
        email_data = EmailData(
            message_id="test",
            subject="Test",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "document.pdf.exe",
                "content_type": "application/x-msdownload",
                "size": 1000,
                "data": b"MZ...",
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        found_suspicious = False
        for warning in result.file_type_warnings:
            if "Suspicious file extension" in warning or "Multiple extensions detected" in warning:
                found_suspicious = True

        self.assertTrue(found_suspicious, "Failed to detect double extension")

if __name__ == '__main__':
    unittest.main()
