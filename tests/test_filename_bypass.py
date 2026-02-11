
import unittest
import sys
from unittest.mock import MagicMock
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import IMAPClient
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.utils.config import AnalysisConfig

class TestFilenameBypass(unittest.TestCase):
    def test_sanitize_filename_trailing_dot(self):
        """Test that _sanitize_filename handles trailing dots correctly"""
        dangerous_filename = "malware.exe."
        sanitized = IMAPClient._sanitize_filename(dangerous_filename)

        # Verify trailing dot is removed
        self.assertFalse(sanitized.endswith('.'), "Sanitization failed to remove trailing dot")
        self.assertEqual(sanitized, "malware.exe", "Sanitization did not produce expected output")

    def test_check_file_extension_bypass(self):
        """Test that _check_file_extension is not bypassed by trailing dots"""
        # Mock config
        config = MagicMock(spec=AnalysisConfig)
        config.check_media_attachments = True

        analyzer = MediaAuthenticityAnalyzer(config)

        # Use a dangerous filename with trailing dot
        # This simulates a case where sanitization might be bypassed or data comes from elsewhere
        filename = "malware.php."

        score, warnings = analyzer._check_file_extension(filename)

        # Verify it is detected as dangerous
        is_detected = score >= 5.0
        self.assertTrue(is_detected, f"Dangerous file '{filename}' was not detected as high risk (Score: {score})")
        self.assertTrue(any("Dangerous file type" in w for w in warnings), "Missing warning for dangerous file type")

if __name__ == "__main__":
    unittest.main()
