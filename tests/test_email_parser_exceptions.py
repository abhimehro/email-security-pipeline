"""
Tests for exception handling in EmailParser.

Verifies that bare silent exception handlers have been replaced with
specific types + logging, so no errors are swallowed silently.
"""

from datetime import datetime
from email.message import Message
from unittest.mock import MagicMock, patch

from src.modules.email_parser import EmailParser, EmailParserConfig
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
    )
    parser = EmailParser(config, parser_config=EmailParserConfig())
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
        # Make sure it doesn't look like an attachment
        msg.get.return_value = ""
        msg.get_filename.return_value = None
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

        # Check that warning about decode error was logged
        warning_calls = parser.logger.warning.call_args_list
        decode_warning = [
            call
            for call in warning_calls
            if "Failed to decode email payload" in call[0][0]
        ]
        assert len(decode_warning) == 1
        assert "email_001" in decode_warning[0][0][0]

    def test_generic_exception_is_logged_as_error(self):
        parser = _make_parser()
        msg = MagicMock(spec=Message)
        msg.get_content_type.return_value = "text/plain"
        msg.get_content_charset.return_value = "utf-8"
        msg.get.return_value = ""
        msg.get_filename.return_value = None
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
            mock_make_header.side_effect = LookupError(
                "unknown encoding: unknown-charset"
            )
            with patch("src.modules.email_parser.logger") as mock_logger:
                result = EmailParser._decode_header_value(raw)
        assert result == raw
        mock_logger.debug.assert_called_once()

    def test_generic_exception_returns_raw_value_and_logs(self):
        """Any other exception must return raw value and log at debug."""
        raw = "=?utf-8?q?some_header?="
        with patch("src.modules.email_parser.make_header") as mock_make_header:
            mock_make_header.side_effect = ValueError("unexpected")
            with patch("src.modules.email_parser.logger") as mock_logger:
                result = EmailParser._decode_header_value(raw)
        assert result == raw
        mock_logger.debug.assert_called_once()
        msg = mock_logger.debug.call_args[0][0]
        assert "ValueError" in msg


# ---------------------------------------------------------------------------
# _process_singlepart_body - Exception handling paths
# ---------------------------------------------------------------------------


class TestProcessSinglepartBody:
    def _make_msg_with_payload(self) -> Message:
        """Build a Message with a valid payload to reach the decode block."""
        msg = MagicMock(spec=Message)
        msg.get_content_type.return_value = "text/plain"
        msg.get_content_charset.return_value = "utf-8"
        msg.get_payload.return_value = b"some raw bytes"
        return msg

    def test_process_singlepart_body_unicode_decode_error(self):
        """Test UnicodeDecodeError is caught and logged as a warning."""
        parser = _make_parser()
        msg = self._make_msg_with_payload()
        body_dict = {"text_parts": [], "html_parts": []}

        with patch.object(
            parser,
            "_decode_bytes",
            side_effect=UnicodeDecodeError(
                "utf-8", b"\xff", 0, 1, "invalid start byte"
            ),
        ):
            from src.modules.email_parser import ParseContext

            ctx = ParseContext(
                safe_email_id="email_003",
                body_dict=body_dict,
                attachments=[],
                current_total_size=0,
            )
            parser._process_singlepart_body(msg, ctx)

        # Warning must have been logged
        parser.logger.warning.assert_called_once()
        warning_msg = parser.logger.warning.call_args[0][0]
        assert "Failed to decode email payload" in warning_msg
        assert "email_003" in warning_msg

    def test_process_singlepart_body_generic_exception(self):
        """Test general exceptions are caught and logged as an error."""
        parser = _make_parser()
        msg = self._make_msg_with_payload()
        body_dict = {"text_parts": [], "html_parts": []}

        from src.modules.email_parser import ParseContext

        ctx = ParseContext(
            safe_email_id="email_004",
            body_dict=body_dict,
            attachments=[],
            current_total_size=0,
        )
        with patch.object(
            parser, "_decode_bytes", side_effect=RuntimeError("Test error")
        ):
            parser._process_singlepart_body(msg, ctx)

        # Error must have been logged
        parser.logger.error.assert_called_once()
        error_msg = parser.logger.error.call_args[0][0]
        assert "Unexpected error extracting content" in error_msg
        assert "email_004" in error_msg
        assert "RuntimeError" in error_msg

    def test_process_singlepart_body_success(self):
        """Test successful decoding and appending of the body."""
        parser = _make_parser()
        msg = self._make_msg_with_payload()
        body_dict = {"text_parts": [], "html_parts": []}

        from src.modules.email_parser import ParseContext

        ctx = ParseContext(
            safe_email_id="email_005",
            body_dict=body_dict,
            attachments=[],
            current_total_size=0,
        )
        with patch.object(parser, "_decode_bytes", return_value="decoded string"):
            with patch.object(parser, "_add_body_content") as mock_add_body:
                parser._process_singlepart_body(msg, ctx)
                mock_add_body.assert_called_once_with(
                    "text/plain", "decoded string", body_dict, "email_005"
                )
