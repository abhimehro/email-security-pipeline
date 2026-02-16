"""
Tests for structured logging functionality
"""

import unittest
import json
import logging
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.structured_logging import JSONFormatter


class TestJSONFormatter(unittest.TestCase):
    """Test cases for JSONFormatter"""

    def setUp(self):
        """Set up test fixtures"""
        self.formatter = JSONFormatter()

    def test_basic_json_format(self):
        """Test that logs are formatted as valid JSON"""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
            func="test_function"
        )

        result = self.formatter.format(record)
        
        # Should be valid JSON
        data = json.loads(result)
        
        # Check required fields
        self.assertIn("timestamp", data)
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["logger"], "test_logger")
        self.assertEqual(data["message"], "Test message")
        self.assertEqual(data["module"], "test")
        self.assertEqual(data["function"], "test_function")
        self.assertEqual(data["line"], 42)

    def test_exception_logging(self):
        """Test that exceptions are included in JSON output"""
        try:
            raise ValueError("Test error")
        except ValueError:
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=42,
            msg="Error occurred",
            args=(),
            exc_info=exc_info
        )

        result = self.formatter.format(record)
        data = json.loads(result)

        # Should include exception info
        self.assertIn("exception", data)
        self.assertIn("ValueError: Test error", data["exception"])
        self.assertIn("Traceback", data["exception"])

    def test_extra_fields(self):
        """Test that extra fields are included in output"""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Processing email",
            args=(),
            exc_info=None
        )
        
        # Add extra fields
        record.extra_fields = {
            "email_id": "12345",
            "threat_score": 75.5,
            "risk_level": "HIGH"
        }

        result = self.formatter.format(record)
        data = json.loads(result)

        # Extra fields should be present
        self.assertEqual(data["email_id"], "12345")
        self.assertEqual(data["threat_score"], 75.5)
        self.assertEqual(data["risk_level"], "HIGH")

    def test_sensitive_field_redaction(self):
        """Test that sensitive fields are redacted"""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Processing config",
            args=(),
            exc_info=None
        )
        
        # Add fields with sensitive names
        record.extra_fields = {
            "password": "secret123",
            "api_key": "abcd1234",
            "app_password": "mypassword",
            "webhook_url": "https://secret.com/hook",
            "slack_webhook": "https://hooks.slack.com/123",
            "normal_field": "safe_value"
        }

        result = self.formatter.format(record)
        data = json.loads(result)

        # Sensitive fields should be redacted
        self.assertEqual(data["password"], "[REDACTED]")
        self.assertEqual(data["api_key"], "[REDACTED]")
        self.assertEqual(data["app_password"], "[REDACTED]")
        self.assertEqual(data["webhook_url"], "[REDACTED]")
        self.assertEqual(data["slack_webhook"], "[REDACTED]")
        
        # Normal fields should not be redacted
        self.assertEqual(data["normal_field"], "safe_value")

    def test_case_insensitive_redaction(self):
        """Test that redaction works regardless of case"""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test",
            args=(),
            exc_info=None
        )
        
        record.extra_fields = {
            "PASSWORD": "secret",
            "Api_Key": "key123",
            "APP_password": "pass"
        }

        result = self.formatter.format(record)
        data = json.loads(result)

        # All variations should be redacted
        self.assertEqual(data["PASSWORD"], "[REDACTED]")
        self.assertEqual(data["Api_Key"], "[REDACTED]")
        self.assertEqual(data["APP_password"], "[REDACTED]")

    def test_different_log_levels(self):
        """Test formatting for different log levels"""
        levels = [
            (logging.DEBUG, "DEBUG"),
            (logging.INFO, "INFO"),
            (logging.WARNING, "WARNING"),
            (logging.ERROR, "ERROR"),
            (logging.CRITICAL, "CRITICAL")
        ]

        for level_int, level_name in levels:
            record = logging.LogRecord(
                name="test_logger",
                level=level_int,
                pathname="test.py",
                lineno=42,
                msg="Test message",
                args=(),
                exc_info=None
            )

            result = self.formatter.format(record)
            data = json.loads(result)

            self.assertEqual(data["level"], level_name)

    def test_no_extra_fields(self):
        """Test that formatter works when no extra fields are present"""
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None
        )

        # Don't add extra_fields attribute
        result = self.formatter.format(record)
        
        # Should still produce valid JSON
        data = json.loads(result)
        self.assertEqual(data["message"], "Test message")


if __name__ == '__main__':
    unittest.main()
