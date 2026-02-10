
import unittest
import sys
import os
from unittest.mock import MagicMock

# Mock numpy and cv2 before importing modules
sys.modules['numpy'] = MagicMock()
sys.modules['cv2'] = MagicMock()

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import IMAPClient
from src.utils.config import AnalysisConfig

class TestMediaExtensionSecurity(unittest.TestCase):
    def setUp(self):
        # Mock config
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = False

        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def test_imap_sanitization_trailing_dot(self):
        """Test that IMAPClient sanitizes trailing dots"""
        # Test cases: (input, expected)
        test_cases = [
            ("malware.exe.", "malware.exe"),
            ("test.php.", "test.php"),
            ("file...", "file"),
            ("archive.tar.gz.", "archive.tar.gz"),
            ("hidden..file", "hidden.file"),
            ("...weird", "weird"),
            ("normal.txt", "normal.txt")
        ]

        for input_name, expected in test_cases:
            with self.subTest(input_name=input_name):
                sanitized = IMAPClient._sanitize_filename(input_name)
                self.assertEqual(sanitized, expected, f"Sanitization failed for '{input_name}'")

    def test_analyzer_extension_check_bypass(self):
        """Test that analyzer detects dangerous extensions even with obfuscation"""
        dangerous_files = [
            "malware.exe",
            "malware.exe.",
            "malware.exe..",
            "script.sh.",
            "test.php.",
            "macro.docm.",
            "suspicious.pdf.exe."
        ]

        for filename in dangerous_files:
            with self.subTest(filename=filename):
                score, warnings = self.analyzer._check_file_extension(filename)

                # Should have high score (>= 5.0) or at least medium (>= 3.0) for suspicious
                is_detected = score >= 3.0
                has_warning = any("Dangerous" in w or "Suspicious" in w or "Multiple extensions" in w for w in warnings)

                self.assertTrue(is_detected, f"Failed to detect dangerous file: {filename} (score={score})")
                self.assertTrue(has_warning, f"Missing warning for: {filename}")

    def test_analyzer_safe_files(self):
        """Test that safe files are not flagged incorrectly"""
        safe_files = [
            "image.jpg",
            "document.pdf",
            "archive.zip",
            "video.mp4"
        ]

        for filename in safe_files:
            with self.subTest(filename=filename):
                score, warnings = self.analyzer._check_file_extension(filename)
                self.assertEqual(score, 0.0, f"Safe file flagged: {filename}")
                self.assertEqual(len(warnings), 0, f"Safe file has warnings: {filename}")

if __name__ == '__main__':
    unittest.main()
