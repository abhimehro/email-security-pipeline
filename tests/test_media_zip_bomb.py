import unittest
import zipfile
import io
import sys
import os
import struct
from datetime import datetime
from unittest.mock import MagicMock

# Add root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaZipBomb(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = False
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def _create_zip_bomb(self, spoof_headers=True):
        # Create a zip file with a large nested file (20MB of zeros)
        # We name it .zip so the analyzer tries to recurse into it
        nested_filename = "nested.zip"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(nested_filename, b"0" * 20 * 1024 * 1024)

        zip_content = bytearray(buffer.getvalue())

        if spoof_headers:
            # Spoof the uncompressed size in the headers to bypass the check
            # Local Header
            lh_idx = zip_content.find(b'PK\x03\x04')
            if lh_idx != -1:
                # Uncompressed size at offset 22
                struct.pack_into('<I', zip_content, lh_idx + 22, 100)

            # Central Directory
            cd_idx = zip_content.find(b'PK\x01\x02')
            if cd_idx != -1:
                # Uncompressed size at offset 24
                struct.pack_into('<I', zip_content, cd_idx + 24, 100)

        return bytes(zip_content)

    def test_zip_bomb_detection(self):
        """Test that a zip bomb (large uncompressed size with spoofed header) is detected"""
        zip_content = self._create_zip_bomb(spoof_headers=True)

        email_data = EmailData(
            message_id="test_bomb",
            subject="Test Zip Bomb",
            sender="attacker@example.com",
            recipient="victim@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "bomb.zip",
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

        found_warning = False
        for warning in result.suspicious_attachments:
            # We accept "Failed to inspect nested archive" as well, which is how our secure reader handles CRC/format errors
            if "Zip bomb detected" in warning or "exceeds maximum size" in warning or "Failed to inspect nested" in warning:
                found_warning = True
                break

        if not found_warning:
            print(f"\nDEBUG: Warnings found: {result.suspicious_attachments}")

        self.assertTrue(found_warning, "Failed to detect zip bomb or handling error")
        # Note: If it fails with CRC error (due to spoofing), the score might be 3.0 + 2.0 (nested) = 5.0
        # If it triggers the bomb detector directly, it's also 5.0+
        self.assertGreaterEqual(result.threat_score, 5.0, "Threat score should be high for zip bomb")

    def test_honest_large_file_skipped(self):
        """Test that a nested zip declaring > 10MB is skipped safely (no bomb warning)"""
        # Create honest large zip (no spoofing)
        zip_content = self._create_zip_bomb(spoof_headers=False)

        email_data = EmailData(
            message_id="test_honest",
            subject="Test Honest Zip",
            sender="user@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "honest.zip",
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

        # Should NOT have "Zip bomb detected" or "Failed to inspect"
        found_bomb_warning = False
        for warning in result.suspicious_attachments:
            if "Zip bomb detected" in warning or "Failed to inspect" in warning:
                found_bomb_warning = True
                break

        self.assertFalse(found_bomb_warning, f"Honest large file was flagged as bomb: {result.suspicious_attachments}")

        # Threat score should be lower (might be 2.0 for nested archive, but not 5.0)
        # Note: 2.0 comes from "nested archive" check which runs before inspection.
        # "Zip honest.zip contains nested archive: nested.zip"
        self.assertLess(result.threat_score, 5.0, "Honest large file should not trigger high threat score")

if __name__ == '__main__':
    unittest.main()
