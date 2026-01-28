"""
Tests for Sanitization Utility
"""

import unittest
from src.utils.sanitization import sanitize_for_logging

class TestSanitization(unittest.TestCase):

    def test_basic_sanitization(self):
        """Test basic string sanitization"""
        self.assertEqual(sanitize_for_logging("Hello World"), "Hello World")
        self.assertEqual(sanitize_for_logging(""), "")
        self.assertEqual(sanitize_for_logging(None), "")

    def test_newline_sanitization(self):
        """Test that newlines are escaped"""
        self.assertEqual(
            sanitize_for_logging("Line 1\nLine 2"),
            "Line 1\\nLine 2"
        )
        self.assertEqual(
            sanitize_for_logging("Line 1\rLine 2"),
            "Line 1\\rLine 2"
        )
        self.assertEqual(
            sanitize_for_logging("Line 1\r\nLine 2"),
            "Line 1\\r\\nLine 2"
        )

    def test_control_character_sanitization(self):
        """Test that control characters are removed"""
        # ASCII 07 (Bell)
        self.assertEqual(sanitize_for_logging("Ding\x07"), "Ding")
        # ANSI Escape Code (Color Red)
        self.assertEqual(sanitize_for_logging("\x1b[31mRed\x1b[0m"), "Red")

    def test_unicode_normalization(self):
        """Test unicode normalization"""
        # Compatibility decomposition
        # 'ﬁ' (ligature) -> 'fi'
        self.assertEqual(sanitize_for_logging("ﬁle"), "file")

    def test_truncation(self):
        """Test string truncation"""
        text = "This is a long string that should be truncated"
        sanitized = sanitize_for_logging(text, max_length=10)
        self.assertEqual(sanitized, "This is a ...")
        self.assertTrue(len(sanitized) <= 13) # 10 + 3 dots

    def test_large_input_truncation(self):
        """Test that large inputs are truncated correctly"""
        # Create a large string that exceeds the early truncation threshold (4 * 255 = 1020)
        large_text = "A" * 2000
        sanitized = sanitize_for_logging(large_text, max_length=255)

        # It should still respect the final max_length
        self.assertEqual(len(sanitized), 255 + 3) # 255 + "..."
        self.assertEqual(sanitized[:255], "A" * 255)
        self.assertTrue(sanitized.endswith("..."))

    def test_large_input_with_expansion(self):
        """Test large input with expansion characters"""
        # Input larger than threshold (10 * 4 = 40)
        text = "\n" * 100
        sanitized = sanitize_for_logging(text, max_length=10)
        # Should be truncated to 10 + "..."
        self.assertEqual(len(sanitized), 13)
        self.assertEqual(sanitized, "\\n" * 5 + "...")

if __name__ == '__main__':
    unittest.main()
