
import unittest
from unittest.mock import MagicMock
from datetime import datetime
import sys
import os

# Add root to path so we can import src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer, MediaAnalysisResult
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaMagicBytes(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def _create_email(self, filename, content, content_type):
        return EmailData(
            message_id="test",
            subject="test",
            sender="sender",
            recipient="recipient",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": filename,
                "content_type": content_type,
                "size": len(content),
                "data": content,
                "truncated": False
            }],
            raw_email=None,
            account_email="me",
            folder="inbox"
        )

    def test_valid_mp4(self):
        # Valid MP4 signature (ftyp at offset 4)
        content = b"\x00\x00\x00\x20ftypmp42" + b"\x00" * 2000
        email = self._create_email("valid.mp4", content, "video/mp4")
        result = self.analyzer.analyze(email)

        self.assertEqual(result.file_type_warnings, [])
        self.assertEqual(result.suspicious_attachments, [])

    def test_invalid_mp4(self):
        # Invalid content
        content = b"Not a video" + b"\x00" * 2000
        email = self._create_email("fake.mp4", content, "video/mp4")
        result = self.analyzer.analyze(email)

        # Should have mismatch warning
        self.assertTrue(any("Invalid file signature" in s for s in result.suspicious_attachments))
        self.assertGreaterEqual(result.threat_score, 5.0)

    def test_valid_avi(self):
        # Valid AVI: RIFF....AVI
        content = b"RIFF" + b"\x00\x00\x00\x00" + b"AVI " + b"\x00" * 2000
        email = self._create_email("valid.avi", content, "video/x-msvideo")
        result = self.analyzer.analyze(email)
        self.assertEqual(result.suspicious_attachments, [])

    def test_valid_wav(self):
        # Valid WAV: RIFF....WAVE
        content = b"RIFF" + b"\x00\x00\x00\x00" + b"WAVE" + b"\x00" * 2000
        email = self._create_email("valid.wav", content, "audio/wav")
        result = self.analyzer.analyze(email)
        self.assertEqual(result.suspicious_attachments, [])

    def test_valid_mkv(self):
        # Valid MKV: 1A 45 DF A3
        content = b"\x1a\x45\xdf\xa3" + b"\x00" * 2000
        email = self._create_email("valid.mkv", content, "video/x-matroska")
        result = self.analyzer.analyze(email)
        self.assertEqual(result.suspicious_attachments, [])

    def test_exe_disguised_as_mp4(self):
        # EXE signature
        content = b"MZ" + b"\x00" * 2000
        email = self._create_email("game.mp4", content, "video/mp4")
        result = self.analyzer.analyze(email)

        self.assertTrue(any("Executable disguised" in s for s in result.suspicious_attachments))
        self.assertGreaterEqual(result.threat_score, 5.0)

if __name__ == "__main__":
    unittest.main()
