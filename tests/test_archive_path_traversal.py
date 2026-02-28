import unittest
import zipfile
import io
import tarfile
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig
from unittest.mock import MagicMock

class TestArchivePathTraversal(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = False
        self.config.media_analysis_timeout = 60
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def test_zip_path_traversal_sanitization(self):
        """Test that malicious path components in zip member names are sanitized in warnings"""

        # Create a zip file in memory containing a malicious filename
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            # Dangerous extension so it generates a warning
            malicious_name = "../../etc/passwd/malicious.exe"
            zf.writestr(malicious_name, b"MZ") # Fake exe header

        zip_data = zip_buffer.getvalue()

        # Create mock email data
        attachment = {
            'filename': 'test.zip',
            'content_type': 'application/zip',
            'size': len(zip_data),
            'data': zip_data
        }

        email_data = EmailData(
            message_id="123",
            subject="Test",
            sender="test@test.com",
            recipient="test@test.com",
            date="2023-01-01",
            body_text="",
            body_html="",
            headers={},
            attachments=[attachment],
            raw_email=None,
            account_email="",
            folder=""
        )

        result = self.analyzer.analyze(email_data)

        # Check warnings
        self.assertTrue(result.threat_score >= 5.0)
        found_warning = False
        for warning in result.suspicious_attachments:
            if "Archive test.zip contains dangerous file:" in warning:
                # The filename should be sanitized (e.g., etcpasswdmalicious.exe)
                # It should absolutely NOT contain ../ or /
                self.assertNotIn("../", warning)
                self.assertNotIn("/", warning.split("dangerous file: ")[1])
                found_warning = True

        self.assertTrue(found_warning, "Expected to find a warning about the dangerous file")

    def test_tar_path_traversal_sanitization(self):
        """Test that malicious path components in tar member names are sanitized in warnings"""

        # Create a tar file in memory
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tf:
            malicious_name = "../../etc/shadow/virus.exe"
            content = b"MZ"
            info = tarfile.TarInfo(name=malicious_name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))

        tar_data = tar_buffer.getvalue()

        # Create mock email data
        attachment = {
            'filename': 'test.tar',
            'content_type': 'application/x-tar',
            'size': len(tar_data),
            'data': tar_data
        }

        email_data = EmailData(
            message_id="123",
            subject="Test",
            sender="test@test.com",
            recipient="test@test.com",
            date="2023-01-01",
            body_text="",
            body_html="",
            headers={},
            attachments=[attachment],
            raw_email=None,
            account_email="",
            folder=""
        )

        result = self.analyzer.analyze(email_data)

        # Check warnings
        self.assertTrue(result.threat_score >= 5.0)
        found_warning = False
        for warning in result.suspicious_attachments:
            if "Archive test.tar contains dangerous file:" in warning:
                self.assertNotIn("../", warning)
                self.assertNotIn("\n", warning)
                found_warning = True

        self.assertTrue(found_warning, "Expected to find a warning about the dangerous file")

if __name__ == '__main__':
    unittest.main()
