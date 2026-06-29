"""
Tests for structured logging functionality.
"""

import json
import logging
import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.structured_logging import JSONFormatter


class TestJSONFormatter(unittest.TestCase):
    """Test cases for JSONFormatter."""

    def setUp(self):
        """Set up test fixtures."""
        self.formatter = JSONFormatter()

    def _create_record(
        self,
        level=logging.INFO,
        msg="Test message",
        args=(),
        exc_info=None,
        func="test_function",
        **kwargs
    ):
        record = logging.LogRecord(
            name="test_logger",
            level=level,
            pathname="test.py",
            lineno=42,
            msg=msg,
            args=args,
            exc_info=exc_info,
            func=func,
        )
        for k, v in kwargs.items():
            setattr(record, k, v)
        return record

    def test_basic_json_format(self):
        """Test that logs are formatted as valid JSON."""
        record = self._create_record()

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
        """Test that exceptions are included in JSON output."""
        try:
            raise ValueError("Test error")
        except ValueError:
            exc_info = sys.exc_info()

        record = self._create_record(
            level=logging.ERROR, msg="Error occurred", exc_info=exc_info
        )

        result = self.formatter.format(record)
        data = json.loads(result)

        # Should include exception info
        self.assertIn("exception", data)
        self.assertIn("ValueError: Test error", data["exception"])
        self.assertIn("Traceback", data["exception"])

    def test_extra_fields(self):
        """Test that extra fields are included in output."""
        record = self._create_record(msg="Processing email")

        # Add extra fields
        record.extra_fields = {
            "email_id": "12345",
            "threat_score": 75.5,
            "risk_level": "HIGH",
        }

        result = self.formatter.format(record)
        data = json.loads(result)

        # Extra fields should be present
        self.assertEqual(data["email_id"], "12345")
        self.assertEqual(data["threat_score"], 75.5)
        self.assertEqual(data["risk_level"], "HIGH")

    def test_sensitive_field_redaction(self):
        """Test that sensitive fields are redacted."""
        record = self._create_record(msg="Processing config")

        # Add fields with sensitive names
        record.extra_fields = {
            "password": "secret123",
            "api_key": "abcd1234",
            "app_password": "mypassword",
            "webhook_url": "https://secret.com/hook",
            "slack_webhook": "https://hooks.slack.com/123",
            "normal_field": "safe_value",
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
        """Test that redaction works regardless of case."""
        record = self._create_record(msg="Test")

        record.extra_fields = {
            "PASSWORD": "secret",
            "Api_Key": "key123",
            "APP_password": "pass",
        }

        result = self.formatter.format(record)
        data = json.loads(result)

        # All variations should be redacted
        self.assertEqual(data["PASSWORD"], "[REDACTED]")
        self.assertEqual(data["Api_Key"], "[REDACTED]")
        self.assertEqual(data["APP_password"], "[REDACTED]")

    def test_different_log_levels(self):
        """Test formatting for different log levels."""
        levels = [
            (logging.DEBUG, "DEBUG"),
            (logging.INFO, "INFO"),
            (logging.WARNING, "WARNING"),
            (logging.ERROR, "ERROR"),
            (logging.CRITICAL, "CRITICAL"),
        ]

        for level_int, level_name in levels:
            record = self._create_record(level=level_int)

            result = self.formatter.format(record)
            data = json.loads(result)

            self.assertEqual(data["level"], level_name)

    def test_no_extra_fields(self):
        """Test that formatter works when no extra fields are present."""
        record = self._create_record()

        # Don't add extra_fields attribute
        result = self.formatter.format(record)

        # Should still produce valid JSON
        data = json.loads(result)
        self.assertEqual(data["message"], "Test message")

    def test_unserializable_extra_fields(self):
        """Test that non-serializable objects in extra fields are converted to strings."""

        class UnserializableObject:
            def __str__(self):
                return "<UnserializableObject instance>"

        record = self._create_record(msg="Testing object serialization")

        record.extra_fields = {
            "custom_obj": UnserializableObject(),
            "normal_field": "test",
        }

        result = self.formatter.format(record)
        data = json.loads(result)

        self.assertEqual(data["custom_obj"], "<UnserializableObject instance>")
        self.assertEqual(data["normal_field"], "test")

    def test_message_with_args(self):
        """Test that messages with formatting arguments are correctly interpolated."""
        record = self._create_record(
            msg="User %s logged in from %s", args=("admin", "192.168.1.1")
        )

        result = self.formatter.format(record)
        data = json.loads(result)

        self.assertEqual(data["message"], "User admin logged in from 192.168.1.1")

    def test_custom_datefmt(self):
        """Test that custom date formats are respected."""
        formatter = JSONFormatter(datefmt="%Y-%m-%d")
        record = self._create_record(msg="Testing date format", created=1609459200)

        result = formatter.format(record)
        data = json.loads(result)

        # We can't guarantee the exact timezone of the environment running the test,
        # but we can check it matches the format "YYYY-MM-DD"
        self.assertRegex(data["timestamp"], r"^\d{4}-\d{2}-\d{2}$")

    def test_empty_message_and_args(self):
        """Test formatting with an empty message and no args."""
        record = self._create_record(msg="")

        result = self.formatter.format(record)
        data = json.loads(result)
        self.assertEqual(data["message"], "")

    def test_malformed_extra_fields(self):
        """Test formatting with non-string keys in extra_fields."""
        record = self._create_record(msg="Testing malformed extra fields")
        record.extra_fields = {123: "numeric key", None: "none key"}

        result = self.formatter.format(record)
        data = json.loads(result)
        self.assertEqual(data["123"], "numeric key")
        self.assertEqual(data["null"], "none key")


if __name__ == "__main__":
    unittest.main()
