import unittest
import zipfile
import io
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock

# Add root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaZipSecurity(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def _create_zip_with_file(self, filename_inside):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zf:
            zf.writestr(filename_inside, b"malicious content")
        return buffer.getvalue()

    def test_zip_containing_exe(self):
        """Test that a zip file containing an executable is flagged"""
        zip_content = self._create_zip_with_file("payload.exe")

        email_data = EmailData(
            message_id="test",
            subject="Test Zip",
            sender="attacker@example.com",
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "innocent.zip",
                "content_type": "application/zip",
                "size": len(zip_content),
                "data": zip_content,
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        # Expectation: Threat score should be high because it contains .exe
        found_warning = False
        for warning in result.suspicious_attachments:
            if "contains dangerous file" in warning:
                found_warning = True
                break

        # Check both lists as implementation might vary
        if not found_warning:
            for warning in result.file_type_warnings:
                if "contains dangerous file" in warning:
                    found_warning = True
                    break

        self.assertTrue(found_warning, "Failed to detect dangerous file inside zip archive")
        self.assertGreaterEqual(result.threat_score, 5.0, "Threat score should be high for malware in zip")

    def test_zip_containing_safe_file(self):
        """Test that a zip file containing a text file is NOT flagged"""
        zip_content = self._create_zip_with_file("notes.txt")

        email_data = EmailData(
            message_id="test",
            subject="Test Zip",
            sender="friend@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "notes.zip",
                "content_type": "application/zip",
                "size": len(zip_content),
                "data": zip_content,
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        # Should be safe
        self.assertEqual(result.threat_score, 0.0)
        self.assertEqual(result.suspicious_attachments, [])

    def test_nested_archive_scored_once(self):
        """Test that a nested archive is scored exactly once (2.0), not twice (4.0).

        SECURITY STORY: Prevents false positives where legitimate nested archives
        (e.g., backup.zip containing archive.tar.gz) receive inflated threat scores,
        reducing alert fatigue and improving analyst trust in the system.
        """
        zip_content = self._create_zip_with_file("backup.tar.gz")

        email_data = EmailData(
            message_id="test",
            subject="Test Zip",
            sender="user@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "archive.zip",
                "content_type": "application/zip",
                "size": len(zip_content),
                "data": zip_content,
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        # Nested archive should add exactly 2.0, not 4.0 from a duplicate check
        self.assertEqual(result.threat_score, 2.0,
                         "Nested archive should be scored exactly once (2.0), not twice (4.0)")

        # Exactly one warning for the nested archive
        nested_warnings = [w for w in result.suspicious_attachments if "contains nested archive" in w]
        self.assertEqual(len(nested_warnings), 1,
                         "Should produce exactly one nested archive warning, not two")

if __name__ == '__main__':
    unittest.main()
