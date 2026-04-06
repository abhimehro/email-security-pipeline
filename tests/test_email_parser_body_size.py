"""
Direct unit tests for EmailParser._append_body_part and _add_body_content.

SECURITY STORY: Both methods are the sole guards against memory exhaustion
from crafted emails with oversized bodies.  A regression — e.g., changing
`>` to `>=` in the size check, or computing `remaining` incorrectly — would
silently allow unbounded body growth.  These tests pin the exact truncation
contracts so any accidental weakening is caught immediately.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.modules.email_parser import EmailParser
from src.utils.config import EmailAccountConfig

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SMALL_MAX = 100  # bytes – keeps test data short and truncation easy to hit


def _make_parser(max_body_size: int = _SMALL_MAX) -> EmailParser:
    """Return an EmailParser with a mocked logger and a small body size limit."""
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
    parser = EmailParser(config, max_body_size=max_body_size)
    parser.logger = MagicMock()
    return parser


def _make_body_dict() -> dict:
    """Return a fresh body accumulator dict as used by _add_body_content."""
    return {
        "text_parts": [],
        "html_parts": [],
        "text_len": 0,
        "html_len": 0,
    }


# ---------------------------------------------------------------------------
# TestAppendBodyPart – direct tests for _append_body_part
# ---------------------------------------------------------------------------


class TestAppendBodyPart(unittest.TestCase):
    """
    Tests for EmailParser._append_body_part.

    The method signature is:
        _append_body_part(parts, current_len, new_part, body_type, safe_email_id)
            -> (updated_parts, updated_len)

    Key contract:
        remaining = max_body_size - current_len
        if len(new_part) > remaining  → truncate to remaining, log warning
        else                          → append unchanged, no warning
    """

    def setUp(self):
        self.parser = _make_parser(max_body_size=_SMALL_MAX)

    # -- fitting parts (no truncation) --------------------------------------

    def test_part_smaller_than_remaining_appended_unchanged(self):
        """A part shorter than the remaining budget is appended as-is."""
        parts = []
        new_part = "x" * 40  # 40 bytes; remaining = 100 − 0 = 100
        updated_parts, updated_len = self.parser._append_body_part(
            parts, 0, new_part, "Body text", "test-id"
        )
        self.assertEqual(updated_parts, [new_part])
        self.assertEqual(updated_len, 40)
        self.parser.logger.warning.assert_not_called()

    def test_part_exactly_at_remaining_boundary_not_truncated(self):
        """
        Boundary condition: len(new_part) == remaining.

        The guard uses strict `>`, so an exactly-fitting part must NOT be
        truncated and NO warning must be logged.
        """
        parts = []
        new_part = "y" * _SMALL_MAX  # len == remaining (100 − 0 = 100)
        updated_parts, updated_len = self.parser._append_body_part(
            parts, 0, new_part, "Body text", "test-id"
        )
        self.assertEqual(updated_parts, [new_part])
        self.assertEqual(updated_len, _SMALL_MAX)
        self.parser.logger.warning.assert_not_called()

    # -- oversized parts (truncation) ---------------------------------------

    def test_part_one_byte_over_remaining_is_truncated(self):
        """
        Off-by-one: len(new_part) == remaining + 1 must trigger truncation.

        This guards against changing `>` to `>=`, which would incorrectly
        truncate exactly-fitting content.
        """
        parts = []
        new_part = "z" * (_SMALL_MAX + 1)  # 101 bytes; remaining = 100
        updated_parts, updated_len = self.parser._append_body_part(
            parts, 0, new_part, "Body text", "test-id"
        )
        self.assertEqual(len(updated_parts), 1)
        self.assertEqual(len(updated_parts[0]), _SMALL_MAX)  # exactly 100
        self.assertEqual(updated_len, _SMALL_MAX)
        self.parser.logger.warning.assert_called_once()

    def test_part_much_larger_than_remaining_truncated_to_exact_remaining(self):
        """A very large part is truncated to exactly `remaining`, not less."""
        current_len = 60
        remaining = _SMALL_MAX - current_len  # 40 bytes
        new_part = "a" * 500  # far exceeds remaining
        updated_parts, updated_len = self.parser._append_body_part(
            [], current_len, new_part, "Body HTML", "test-id"
        )
        self.assertEqual(len(updated_parts[0]), remaining)
        self.assertEqual(updated_len, _SMALL_MAX)
        self.parser.logger.warning.assert_called_once()

    def test_zero_remaining_appends_empty_string_with_warning(self):
        """
        When current_len == max_body_size, remaining == 0.

        The part (non-empty) exceeds remaining, so it is truncated to an
        empty string and a warning is still logged.
        """
        parts = []
        updated_parts, updated_len = self.parser._append_body_part(
            parts, _SMALL_MAX, "overflow", "Body text", "test-id"
        )
        self.assertEqual(updated_parts, [""])
        self.assertEqual(updated_len, _SMALL_MAX)
        self.parser.logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# TestAddBodyContent – direct tests for _add_body_content
# ---------------------------------------------------------------------------


class TestAddBodyContent(unittest.TestCase):
    """
    Tests for EmailParser._add_body_content.

    The method signature is:
        _add_body_content(content_type, part_data, body_dict, safe_email_id)
            -> None  (mutates body_dict in place)

    Key contracts:
        content_type == 'text/html' → accumulates into html_parts / html_len
        anything else               → accumulates into text_parts / text_len
        current_len >= max_body_size → _append_body_part is NOT called
    """

    def setUp(self):
        self.parser = _make_parser(max_body_size=_SMALL_MAX)

    def test_plain_text_routes_to_text_parts(self):
        """content_type='text/plain' must update text_parts and text_len only."""
        body_dict = _make_body_dict()
        self.parser._add_body_content("text/plain", "hello", body_dict, "id-1")
        self.assertEqual(body_dict["text_parts"], ["hello"])
        self.assertEqual(body_dict["text_len"], 5)
        self.assertEqual(body_dict["html_parts"], [])
        self.assertEqual(body_dict["html_len"], 0)

    def test_html_routes_to_html_parts(self):
        """content_type='text/html' must update html_parts and html_len only."""
        body_dict = _make_body_dict()
        self.parser._add_body_content("text/html", "<b>hi</b>", body_dict, "id-2")
        self.assertEqual(body_dict["html_parts"], ["<b>hi</b>"])
        self.assertEqual(body_dict["html_len"], 9)
        self.assertEqual(body_dict["text_parts"], [])
        self.assertEqual(body_dict["text_len"], 0)

    def test_at_or_over_max_body_size_skips_append(self):
        """
        When current_len >= max_body_size, _append_body_part must NOT be called.

        This validates the early-exit guard that protects the size limit from
        being exceeded via repeated small appends after the limit is reached.
        """
        body_dict = _make_body_dict()
        body_dict["text_len"] = _SMALL_MAX  # already at limit

        with patch.object(self.parser, "_append_body_part") as mock_append:
            self.parser._add_body_content(
                "text/plain", "overflow data", body_dict, "id-3"
            )
            mock_append.assert_not_called()

    def test_non_html_content_type_defaults_to_text_key(self):
        """
        Any content_type other than 'text/html' must route to the text bucket.

        Ensures that unknown MIME subtypes (e.g. text/enriched, text/calendar)
        fall back to text rather than HTML.
        """
        body_dict = _make_body_dict()
        self.parser._add_body_content(
            "text/calendar", "BEGIN:VCALENDAR", body_dict, "id-4"
        )
        self.assertGreater(body_dict["text_len"], 0)
        self.assertEqual(body_dict["html_len"], 0)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
