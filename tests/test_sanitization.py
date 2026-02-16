"""
Tests for Sanitization Utility
"""

import unittest
from src.utils.sanitization import sanitize_for_logging, redact_email

class TestSanitization(unittest.TestCase):

    def test_redact_email(self):
        """Test email redaction"""
        # Standard emails
        self.assertEqual(redact_email("john.doe@example.com"), "j*******@example.com")
        self.assertEqual(redact_email("jane@example.com"), "j***@example.com")

        # Short usernames
        self.assertEqual(redact_email("abc@example.com"), "a**@example.com")
        self.assertEqual(redact_email("ab@example.com"), "a*@example.com")
        self.assertEqual(redact_email("a@example.com"), "*@example.com")

        # Edge cases
        self.assertEqual(redact_email(""), "")
        self.assertEqual(redact_email(None), None)
        self.assertEqual(redact_email("not-an-email"), "not-an-email")

        # Complex emails
        self.assertEqual(
            redact_email("very.long.name+tag@sub.domain.com"),
            "v*****************@sub.domain.com"
        )

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

if __name__ == '__main__':
    unittest.main()
