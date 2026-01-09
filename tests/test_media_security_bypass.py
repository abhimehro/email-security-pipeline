
import unittest
from datetime import datetime
from src.modules.media_analyzer import MediaAuthenticityAnalyzer, MediaAnalysisResult
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaAnalyzerSecurityBypass(unittest.TestCase):
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

        # Subclass to spy on _check_deepfake_indicators
        class SpiedAnalyzer(MediaAuthenticityAnalyzer):
            def _check_deepfake_indicators(self, filename, data, content_type):
                return 1.0, ["DEEPFAKE_CHECK_RAN"]

        self.analyzer = SpiedAnalyzer(self.config)

    def test_disguised_executable_skips_deepfake_check(self):
        """
        Verify that a file named 'harmless.mp4' which is actually an EXE
        is skipped by the deepfake analyzer.
        """
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
                "filename": "harmless.mp4",
                "content_type": "video/mp4",
                "size": 1000,
                "data": b"MZ" + b"\x00"*100, # Mock EXE header
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        # 1. Verify that it detected the mismatch/disguise
        found_mismatch = False
        for warning in result.suspicious_attachments:
            if "Executable disguised" in warning:
                found_mismatch = True
        self.assertTrue(found_mismatch, "Should detect executable disguised as MP4")

        # 2. Verify that deepfake check DID NOT RUN
        ran_deepfake = "DEEPFAKE_CHECK_RAN" in result.potential_deepfakes
        self.assertFalse(ran_deepfake, "Deepfake check should NOT run for dangerous file")

    def test_dangerous_extension_skips_deepfake_check(self):
        """
        Verify that a file with a dangerous extension (e.g. .exe)
        skips deepfake check even if something else triggered it (unlikely but good defense).
        Note: The loop logic in MediaAnalyzer puts `check_deepfake` after `check_extension`.
        """
        # Note: If filename ends with .exe, is_media will be false inside _check_deepfake_indicators
        # so it would skip anyway. But the explicit check adds defense in depth before even calling it.
        # Let's try a double extension like .mp4.exe

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
                "filename": "video.mp4.exe",
                "content_type": "application/x-msdownload",
                "size": 1000,
                "data": b"MZ" + b"\x00"*100,
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        found_dangerous = False
        for warning in result.file_type_warnings:
            if "Dangerous file type" in warning:
                found_dangerous = True
        self.assertTrue(found_dangerous)

        ran_deepfake = "DEEPFAKE_CHECK_RAN" in result.potential_deepfakes
        self.assertFalse(ran_deepfake, "Deepfake check should NOT run for .exe file")

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

if __name__ == '__main__':
    unittest.main()
