"""
Tests for CSV Sanitization
"""

import unittest
from src.utils.sanitization import sanitize_for_csv

class TestCSVSanitization(unittest.TestCase):

    def test_basic_formulas(self):
        """Test basic formula injection patterns"""
        self.assertEqual(sanitize_for_csv("=1+1"), "'=1+1")
        self.assertEqual(sanitize_for_csv("+1+1"), "'+1+1")
        self.assertEqual(sanitize_for_csv("-1+1"), "'-1+1")
        self.assertEqual(sanitize_for_csv("@SUM(1,1)"), "'@SUM(1,1)")
        self.assertEqual(sanitize_for_csv("%100"), "'%100")  # Test % injection

    def test_whitespace_prefix(self):
        """Test dangerous patterns prefixed with whitespace"""
        self.assertEqual(sanitize_for_csv("  =1+1"), "'  =1+1")
        self.assertEqual(sanitize_for_csv("\t=1+1"), "'\t=1+1")
        self.assertEqual(sanitize_for_csv("\n=1+1"), "'\n=1+1")

    def test_advanced_patterns(self):
        """Test advanced injection patterns detected in review"""
        # Tab at start
        self.assertEqual(sanitize_for_csv("\tcmd"), "'\tcmd")
        # Pipe at start
        self.assertEqual(sanitize_for_csv("|cmd"), "'|cmd")
        # Carriage return at start
        self.assertEqual(sanitize_for_csv("\r=cmd"), "'\r=cmd")

    def test_safe_strings(self):
        """Test safe strings are not modified"""
        self.assertEqual(sanitize_for_csv("Hello"), "Hello")
        self.assertEqual(sanitize_for_csv("123"), "123")
        self.assertEqual(sanitize_for_csv(""), "")
        self.assertEqual(sanitize_for_csv(None), "")
        self.assertEqual(sanitize_for_csv("email@example.com"), "email@example.com")

    def test_already_sanitized(self):
        """Test double sanitization (it should quote again if it looks dangerous,
        but usually the quote itself makes it safe)"""
        # If it starts with ', it's safe.
        self.assertEqual(sanitize_for_csv("'=1+1"), "'=1+1")

if __name__ == '__main__':
    unittest.main()
