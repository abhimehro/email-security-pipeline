"""
Tests for exception handling in EmailParser.

Verifies that bare silent exception handlers have been replaced with
specific types + logging, so no errors are swallowed silently.
"""

import logging
from datetime import datetime
from email.message import Message
from unittest.mock import MagicMock, patch

import pytest

from src.modules.email_parser import EmailParser
from src.utils.config import EmailAccountConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_parser() -> EmailParser:
    """Return an EmailParser with a mocked config and logger."""
    config = EmailAccountConfig(
        enabled=True,
        email="test@example.com",
        imap_server="imap.example.com",
        imap_port=993,
        app_password="secret",
        folders=["INBOX"],
        provider="test",
        use_ssl=True,
        verify_ssl=True,
    )
    parser = EmailParser(config)
    parser.logger = MagicMock()
    return parser


# ---------------------------------------------------------------------------
# _extract_singlepart_content – UnicodeDecodeError path
# ---------------------------------------------------------------------------

class TestExtractSinglepartContent:
    def _make_msg_with_bad_payload(self) -> Message:
        """Build a Message whose get_payload(decode=True) raises UnicodeDecodeError."""
        msg = MagicMock(spec=Message)
        msg.get_content_type.return_value = "text/plain"
        msg.get_content_charset.return_value = "utf-8"
        # Simulate UnicodeDecodeError when fetching payload
        msg.get_payload.side_effect = UnicodeDecodeError(
            "utf-8", b"\xff", 0, 1, "invalid start byte"
        )
        return msg

    def test_unicode_decode_error_is_logged_as_warning(self):
        parser = _make_parser()
        msg = self._make_msg_with_bad_payload()
        body_text, body_html, attachments = parser._extract_singlepart_content(
            msg, "email_001"
        )
        # Should return empty content – no crash
        assert body_text == ""
        assert body_html == ""
        assert attachments == []
        # Warning must have been logged
        parser.logger.warning.assert_called_once()
        warning_msg = parser.logger.warning.call_args[0][0]
        assert "email_001" in warning_msg

    def test_generic_exception_is_logged_as_error(self):
        parser = _make_parser()
        msg = MagicMock(spec=Message)
        msg.get_content_type.return_value = "text/plain"
        msg.get_content_charset.return_value = "utf-8"
        msg.get_payload.side_effect = RuntimeError("simulated parser error")

        body_text, body_html, attachments = parser._extract_singlepart_content(
            msg, "email_002"
        )
        assert body_text == ""
        assert body_html == ""
        # Error must have been logged (not silently swallowed)
        parser.logger.error.assert_called_once()
        error_msg = parser.logger.error.call_args[0][0]
        assert "email_002" in error_msg
        assert "RuntimeError" in error_msg


# ---------------------------------------------------------------------------
# _extract_date – logging on parse failure
# ---------------------------------------------------------------------------

class TestExtractDate:
    def test_bad_date_falls_back_and_logs_debug(self):
        parser = _make_parser()
        msg = MagicMock(spec=Message)
        msg.get.return_value = "not-a-real-date"

        result = parser._extract_date(msg)

        # Should return a datetime (fallback to now)
        assert isinstance(result, datetime)
        # Debug message must have been logged
        parser.logger.debug.assert_called_once()
        debug_msg = parser.logger.debug.call_args[0][0]
        assert "not-a-real-date" in debug_msg

    def test_missing_date_header_falls_back_silently(self):
        """An empty Date header still falls back without crashing."""
        parser = _make_parser()
        msg = MagicMock(spec=Message)
        msg.get.return_value = ""

        result = parser._extract_date(msg)
        assert isinstance(result, datetime)


# ---------------------------------------------------------------------------
# _decode_header_value – specific exception paths
# ---------------------------------------------------------------------------

class TestDecodeHeaderValue:
    def test_valid_header_decoded_normally(self):
        result = EmailParser._decode_header_value("hello world")
        assert result == "hello world"

    def test_empty_header_returns_empty_string(self):
        assert EmailParser._decode_header_value("") == ""
        assert EmailParser._decode_header_value(None) == ""  # type: ignore[arg-type]

    def test_unicode_decode_error_returns_raw_value_and_logs(self):
        """A UnicodeDecodeError must return the raw value and log at debug level."""
        raw = "=?bad-charset?b?AAAA?="
        with patch("src.modules.email_parser.make_header") as mock_make_header:
            mock_make_header.side_effect = UnicodeDecodeError(
                "utf-8", b"\xff", 0, 1, "invalid"
            )
            with patch("src.modules.email_parser.logger") as mock_logger:
                result = EmailParser._decode_header_value(raw)
        assert result == raw
        mock_logger.debug.assert_called_once()
        msg = mock_logger.debug.call_args[0][0]
        assert "charset" in msg.lower() or "decode" in msg.lower()

    def test_lookup_error_returns_raw_value_and_logs(self):
        """An unknown charset (LookupError) must return raw value and log at debug."""
        raw = "=?unknown-charset?b?dGVzdA==?="
        with patch("src.modules.email_parser.make_header") as mock_make_header:
            mock_make_header.side_effect = LookupError("unknown encoding: unknown-charset")
            with patch("src.modules.email_parser.logger") as mock_logger:
                result = EmailParser._decode_header_value(raw)
        assert result == raw
        mock_logger.debug.assert_called_once()

    def test_generic_exception_returns_raw_value_and_logs(self):
        """Any other exception must return raw value and log at debug."""
        raw = "some header"
        with patch("src.modules.email_parser.make_header") as mock_make_header:
            mock_make_header.side_effect = ValueError("unexpected")
            with patch("src.modules.email_parser.logger") as mock_logger:
                result = EmailParser._decode_header_value(raw)
        assert result == raw
        mock_logger.debug.assert_called_once()
        msg = mock_logger.debug.call_args[0][0]
        assert "ValueError" in msg
