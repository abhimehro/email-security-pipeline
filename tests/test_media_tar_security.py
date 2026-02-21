import unittest
import tarfile
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

class TestMediaTarSecurity(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def _create_tar_with_file(self, filename_inside):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tf:
            info = tarfile.TarInfo(name=filename_inside)
            info.size = len(b"malicious content")
            tf.addfile(info, io.BytesIO(b"malicious content"))
        return buffer.getvalue()

    def test_tar_containing_exe(self):
        """Test that a tar file containing an executable is flagged"""
        tar_content = self._create_tar_with_file("payload.exe")

        email_data = EmailData(
            message_id="test",
            subject="Test Tar",
            sender="attacker@example.com",
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "archive.tar",
                "content_type": "application/x-tar",
                "size": len(tar_content),
                "data": tar_content,
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

        self.assertTrue(found_warning, "Failed to detect dangerous file inside tar archive")
        self.assertGreaterEqual(result.threat_score, 5.0, "Threat score should be high for malware in tar")

    def test_tar_containing_safe_file(self):
        """Test that a tar file containing a text file is NOT flagged"""
        tar_content = self._create_tar_with_file("notes.txt")

        email_data = EmailData(
            message_id="test",
            subject="Test Tar",
            sender="friend@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "notes.tar",
                "content_type": "application/x-tar",
                "size": len(tar_content),
                "data": tar_content,
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

    def test_tar_with_nested_zip_with_exe(self):
        """Test that a tar file containing a zip with an executable is flagged"""
        # Create zip with exe
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr("payload.exe", b"malicious content")
        zip_content = zip_buffer.getvalue()

        # Create tar with zip
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tf:
            info = tarfile.TarInfo(name="nested.zip")
            info.size = len(zip_content)
            tf.addfile(info, io.BytesIO(zip_content))
        tar_content = tar_buffer.getvalue()

        email_data = EmailData(
            message_id="test",
            subject="Test Nested Tar",
            sender="attacker@example.com",
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "archive.tar",
                "content_type": "application/x-tar",
                "size": len(tar_content),
                "data": tar_content,
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

        # Also check file_type_warnings just in case
        if not found_warning:
            for warning in result.file_type_warnings:
                if "contains dangerous file" in warning:
                    found_warning = True
                    break

        self.assertTrue(found_warning, "Failed to detect dangerous file inside nested zip in tar")

    def test_zip_with_nested_tar_with_exe(self):
        """Test that a zip file containing a tar with an executable is flagged"""
        # Create tar with exe
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tf:
            info = tarfile.TarInfo(name="payload.exe")
            info.size = len(b"malicious content")
            tf.addfile(info, io.BytesIO(b"malicious content"))
        tar_content = tar_buffer.getvalue()

        # Create zip with tar
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr("nested.tar", tar_content)
        zip_content = zip_buffer.getvalue()

        email_data = EmailData(
            message_id="test",
            subject="Test Nested Zip",
            sender="attacker@example.com",
            recipient="victim@example.com",
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

        # Expectation: Threat score should be high because it contains .exe in nested tar
        found_warning = False
        for warning in result.suspicious_attachments:
            if "contains dangerous file" in warning:
                found_warning = True
                break

        self.assertTrue(found_warning, "Failed to detect dangerous file inside nested tar in zip")

if __name__ == '__main__':
    unittest.main()
