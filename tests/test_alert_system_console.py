"""
Alert System Console Rendering Tests
Tests _console_clean_report and its helper methods:
_get_visual_length, _truncate_text, _get_terminal_width
"""

import sys
import unittest
from datetime import datetime
from io import StringIO
from unittest.mock import MagicMock, patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig


def _make_alert_system() -> AlertSystem:
    """Return an AlertSystem wired for console-only output."""
    config = MagicMock(spec=AlertConfig)
    config.console = True
    config.webhook_enabled = False
    config.slack_enabled = False
    config.threat_low = 30
    config.threat_medium = 60
    config.threat_high = 85
    return AlertSystem(config)


def _make_clean_report(**kwargs) -> ThreatReport:
    """Return a ThreatReport with a score below the clean threshold."""
    defaults = dict(
        email_id="test-console-001",
        subject="Meeting Tomorrow",
        sender="alice@example.com",
        recipient="bob@example.com",
        date=datetime.now().isoformat(),
        overall_threat_score=5.0,
        risk_level="low",
        spam_analysis={},
        nlp_analysis={},
        media_analysis={},
        recommendations=[],
        timestamp=datetime.now().isoformat(),
    )
    defaults.update(kwargs)
    return ThreatReport(**defaults)


class TestGetVisualLength(unittest.TestCase):
    """Unit tests for AlertSystem._get_visual_length."""

    def setUp(self):
        self.alert = _make_alert_system()

    def test_plain_text_returns_len(self):
        """Plain text: visual length equals len()."""
        text = "Hello, world!"
        self.assertEqual(self.alert._get_visual_length(text), len(text))

    def test_ansi_codes_not_counted(self):
        """ANSI colour codes should not be included in the visual length.

        SECURITY STORY: Email senders/subjects may contain crafted ANSI sequences
        designed to confuse column-width calculations and misalign the display.
        _get_visual_length must strip them so truncation remains predictable.
        """
        # "\033[31mRed\033[0m" is "Red" wrapped in ANSI red + reset
        ansi_text = "\033[31mRed\033[0m"
        self.assertEqual(self.alert._get_visual_length(ansi_text), 3)

    def test_empty_string_returns_zero(self):
        """Empty string has visual length of 0."""
        self.assertEqual(self.alert._get_visual_length(""), 0)

    def test_multiple_ansi_sequences(self):
        """Multiple ANSI codes within a string are all stripped."""
        text = "\033[1m\033[32mBold Green\033[0m"
        self.assertEqual(self.alert._get_visual_length(text), len("Bold Green"))


class TestTruncateText(unittest.TestCase):
    """Unit tests for AlertSystem._truncate_text."""

    def setUp(self):
        self.alert = _make_alert_system()

    def test_short_text_unchanged(self):
        """Text shorter than width is returned unchanged."""
        self.assertEqual(self.alert._truncate_text("Hi", 10), "Hi")

    def test_exact_width_unchanged(self):
        """Text exactly equal to width is returned unchanged."""
        text = "A" * 20
        self.assertEqual(self.alert._truncate_text(text, 20), text)

    def test_exceeds_width_truncated_with_ellipsis(self):
        """Text exceeding width is truncated and '...' is appended.

        SECURITY STORY: Without truncation, an attacker could supply an
        arbitrarily long sender/subject to overflow terminal line buffers or
        obscure subsequent output.
        """
        text = "A" * 50
        result = self.alert._truncate_text(text, 20)
        self.assertTrue(result.endswith("..."))
        self.assertLessEqual(len(result), 20)

    def test_width_le_3_returns_dots(self):
        """Width ≤ 3 returns '.' repeated width times (edge case)."""
        self.assertEqual(self.alert._truncate_text("Hello", 3), "...")
        self.assertEqual(self.alert._truncate_text("Hello", 2), "..")
        self.assertEqual(self.alert._truncate_text("Hello", 1), ".")

    def test_empty_string_returns_empty(self):
        """Empty string input returns empty string."""
        self.assertEqual(self.alert._truncate_text("", 20), "")


class TestGetTerminalWidth(unittest.TestCase):
    """Unit tests for AlertSystem._get_terminal_width."""

    def setUp(self):
        self.alert = _make_alert_system()

    def test_returns_positive_integer(self):
        """Normal call returns an integer >= 1."""
        width = self.alert._get_terminal_width()
        self.assertIsInstance(width, int)
        self.assertGreaterEqual(width, 1)

    def test_oserror_falls_back_to_80(self):
        """When shutil.get_terminal_size raises OSError, falls back to 80."""
        with patch("shutil.get_terminal_size", side_effect=OSError("no tty")):
            width = self.alert._get_terminal_width()
        self.assertEqual(width, 80)


class TestConsoleCleanReport(unittest.TestCase):
    """Integration tests for AlertSystem._console_clean_report."""

    def setUp(self):
        self.alert = _make_alert_system()

    def test_completes_without_raising(self):
        """_console_clean_report must not raise for a normal report."""
        report = _make_clean_report()
        with patch("sys.stdout", new_callable=StringIO):
            self.alert._console_clean_report(report)  # should not raise

    def test_output_contains_sender(self):
        """Output written to stdout must include the sender address.

        SECURITY STORY: If truncation or sanitisation silently swallows the
        sender entirely, defenders lose key attribution information. We verify
        that the full sender (local-part *and* domain) is visible in the
        rendered line. Terminal width is pinned to a generous value so that
        truncation cannot hide the domain.
        """
        report = _make_clean_report(sender="alice@example.com")
        captured = StringIO()
        with patch.object(self.alert, "_get_terminal_width", return_value=200):
            with patch("sys.stdout", captured):
                self.alert._console_clean_report(report)
        output = captured.getvalue()
        self.assertIn("alice", output)
        self.assertIn("example.com", output)

    def test_invalid_timestamp_does_not_raise(self):
        """A non-ISO timestamp falls back to the raw value in the rendered output."""
        report = _make_clean_report(timestamp="not-a-date")
        captured = StringIO()
        with patch("sys.stdout", captured):
            self.alert._console_clean_report(report)  # should not raise
        output = captured.getvalue()
        self.assertIn("not-a-date", output)

    def test_empty_subject_shows_placeholder(self):
        """An empty subject should display a placeholder, not crash."""
        report = _make_clean_report(subject="")
        captured = StringIO()
        with patch("sys.stdout", captured):
            self.alert._console_clean_report(report)
        output = captured.getvalue()
        self.assertIn("No Subject", output)


if __name__ == "__main__":
    unittest.main()
