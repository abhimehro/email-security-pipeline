import io
import tarfile
import unittest
import zipfile
from unittest.mock import MagicMock

from src.modules.email_ingestion import EmailData
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.utils.config import AnalysisConfig


class TestArchivePathTraversal(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = False
        self.config.media_analysis_timeout = 60
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def _create_archive_and_analyze(self, archive_type: str, member_name: str, content: bytes = b"MZ"):
        archive_buffer = io.BytesIO()
        if archive_type == "zip":
            with zipfile.ZipFile(archive_buffer, "w") as zf:
                zf.writestr(member_name, content)
        elif archive_type == "tar":
            with tarfile.open(fileobj=archive_buffer, mode="w") as tf:
                info = tarfile.TarInfo(name=member_name)
                info.size = len(content)
                tf.addfile(info, io.BytesIO(content))

        archive_data = archive_buffer.getvalue()

        content_type = "application/zip" if archive_type == "zip" else "application/x-tar"
        filename = f"test.{archive_type}"

        email_data = EmailData(
            message_id="123",
            subject="Test",
            sender="test@test.com",
            recipient="test@test.com",
            date="2023-01-01",
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": filename,
                "content_type": content_type,
                "size": len(archive_data),
                "data": archive_data,
            }],
            raw_email=None,
            account_email="",
            folder="",
        )
        return self.analyzer.analyze(email_data), filename

    def _check_sanitization_warning(self, result, filename, disallowed_chars=None, disallowed_after=None):
        prefix = f"Archive {filename} contains dangerous file:"
        matching_warnings = [w for w in result.suspicious_attachments if prefix in w]
        self.assertTrue(len(matching_warnings) > 0, "Expected to find a warning about the dangerous file")

        warning = matching_warnings[0]
        disallowed_chars = disallowed_chars or []
        for char in disallowed_chars:
            self.assertNotIn(char, warning)

        disallowed_after = disallowed_after or []
        if disallowed_after:
            after_part = warning.split("dangerous file: ")[1]
            for char in disallowed_after:
                self.assertNotIn(char, after_part)

    def test_zip_path_traversal_sanitization(self):
        """Test that malicious path components in zip member names are sanitized in warnings."""
        result, filename = self._create_archive_and_analyze("zip", "../../etc/passwd/malicious.exe")
        self.assertTrue(result.threat_score >= 5.0)
        self._check_sanitization_warning(result, filename, disallowed_chars=["../"], disallowed_after=["/"])

    def test_tar_path_traversal_sanitization(self):
        """Test that malicious path components in tar member names are sanitized in warnings."""
        result, filename = self._create_archive_and_analyze("tar", "../../etc/shadow/virus.exe")
        self.assertTrue(result.threat_score >= 5.0)
        self._check_sanitization_warning(result, filename, disallowed_chars=["../", "\n"])

    def test_tar_backward_slash_absolute(self):
        result, _ = self._create_archive_and_analyze("tar", "\\etc\\shadow")
        self.assertTrue(result.threat_score >= 5.0)

    def test_zip_backward_slash_absolute(self):
        result, _ = self._create_archive_and_analyze("zip", "\\etc\\shadow")
        self.assertTrue(result.threat_score >= 5.0)

    def test_zip_windows_drive(self):
        result, _ = self._create_archive_and_analyze("zip", "C:/Windows/System32/cmd.exe")
        self.assertTrue(result.threat_score >= 5.0)


if __name__ == "__main__":
    unittest.main()
