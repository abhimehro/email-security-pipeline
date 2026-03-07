"""
Unit tests for IMAPConnection._parse_email_payload()

SECURITY STORY: _parse_email_payload() is the gatekeeper between raw IMAP
server responses and the rest of the pipeline. Misbehaving IMAP servers can
send unexpected response formats; these tests verify that all four defensive
code paths return the correct value and emit the correct log call so regressions
are caught before they silently drop emails.

PATTERN RECOGNITION: All four paths are exercised directly without a live IMAP
connection — the same isolation pattern used throughout this test suite.
"""

import unittest
from unittest.mock import MagicMock

from src.modules.imap_connection import IMAPConnection
from src.utils.config import EmailAccountConfig


def _make_config(**overrides) -> EmailAccountConfig:
    """Return a minimal EmailAccountConfig suitable for unit tests."""
    defaults = dict(
        enabled=True,
        email="test@example.com",
        imap_server="imap.example.com",
        imap_port=993,
        app_password="secret",
        folders=["INBOX"],
        provider="generic",
        use_ssl=True,
        verify_ssl=True,
    )
    defaults.update(overrides)
    return EmailAccountConfig(**defaults)


class TestParseEmailPayload(unittest.TestCase):
    """Direct unit tests for IMAPConnection._parse_email_payload()."""

    def setUp(self):
        self.conn = IMAPConnection(_make_config())
        self.conn.logger = MagicMock()

    # ------------------------------------------------------------------
    # Path 1: non-tuple input → None, no log calls
    # ------------------------------------------------------------------
    def test_non_tuple_returns_none(self):
        """Path 1: IMAP separator byte (e.g. b')') is not a tuple → skip."""
        result = self.conn._parse_email_payload(b")")
        self.assertIsNone(result)
        self.conn.logger.warning.assert_not_called()
        self.conn.logger.error.assert_not_called()

    # ------------------------------------------------------------------
    # Path 2: normal (header, body) tuple → (email_id_str, raw_bytes)
    # ------------------------------------------------------------------
    def test_normal_tuple_returns_id_and_bytes(self):
        """Path 2: well-formed FETCH response → (seq_number_str, raw_bytes)."""
        header = b"42 (RFC822 {100}"
        body = b"raw email data"
        result = self.conn._parse_email_payload((header, body))
        self.assertEqual(result, ("42", body))
        self.conn.logger.warning.assert_not_called()
        self.conn.logger.error.assert_not_called()

    def test_realistic_header_sequence_number_only(self):
        """Path 2: only the leading sequence number is used as email_id."""
        header = b"1234 (RFC822 {512}"
        body = b"full raw email bytes here"
        result = self.conn._parse_email_payload((header, body))
        self.assertIsNotNone(result)
        email_id, raw = result
        self.assertEqual(email_id, "1234")
        self.assertEqual(raw, body)

    # ------------------------------------------------------------------
    # Path 3: body is not bytes → None + logger.warning called once
    # ------------------------------------------------------------------
    def test_non_bytes_body_returns_none_and_warns(self):
        """Path 3: unexpected string body triggers warning and returns None."""
        header = b"7 (RFC822 {50}"
        body = "this should be bytes, not a str"
        result = self.conn._parse_email_payload((header, body))
        self.assertIsNone(result)
        self.conn.logger.warning.assert_called_once()
        self.conn.logger.error.assert_not_called()

    # ------------------------------------------------------------------
    # Path 4: malformed header → None + logger.error called once
    # ------------------------------------------------------------------
    def test_empty_header_returns_none_and_logs_error(self):
        """Path 4: empty header bytes causes split()[0] to raise → error logged."""
        result = self.conn._parse_email_payload((b"", b"data"))
        self.assertIsNone(result)
        self.conn.logger.error.assert_called_once()
        self.conn.logger.warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
