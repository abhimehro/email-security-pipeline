"""Tests for ColoredFormatter in src/utils/logging_utils.

SECURITY STORY: ColoredFormatter applies ANSI codes to every log record
emitted by the pipeline. A broken formatter can silently swallow or corrupt
log output, making it harder for operators to detect threats in real time.
These tests pin the formatter's colorization logic so that any accidental
regression is caught before it reaches production.
"""

import importlib
import logging
import os
import unittest
from unittest.mock import MagicMock, patch

from src.utils import colors, logging_utils


class TestColoredFormatter(unittest.TestCase):
    """Unit tests for ColoredFormatter."""

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _reload_with_tty(self):
        """Reload colors and logging_utils as if running in a real TTY.

        Returns a (ColoredFormatter class, Colors class) pair where every
        color constant holds a real ANSI escape code rather than "".
        """
        mock_stdout = MagicMock()
        mock_stdout.isatty.return_value = True

        with patch("sys.stdout", mock_stdout):
            with patch.dict(os.environ):
                # Ensure NO_COLOR is absent so TTY detection wins.
                os.environ.pop("NO_COLOR", None)
                importlib.reload(colors)
                importlib.reload(logging_utils)
                # Capture the just-reloaded classes before exiting the context.
                Formatter = logging_utils.ColoredFormatter
                C = colors.Colors
        return Formatter, C

    def tearDown(self):
        """Restore both modules to their natural (non-TTY) state after each test."""
        importlib.reload(colors)
        importlib.reload(logging_utils)

    @staticmethod
    def _make_record(msg, level=logging.INFO):
        """Return a minimal LogRecord for the given message and level."""
        return logging.LogRecord(
            name="test",
            level=level,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )

    # ------------------------------------------------------------------ #
    # Level colorization                                                   #
    # ------------------------------------------------------------------ #
    # Note: format() operates on a copy of the record (copy.copy guard),
    # so color codes appear in the *returned string*, not in record.msg /
    # record.levelname directly.
    # We use a format string that emits the levelname so we can assert
    # that the right ANSI color was injected.

    def test_debug_level_gets_grey(self):
        """DEBUG records have the GREY color code injected into levelname."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("hello", level=logging.DEBUG)
        output = Formatter("%(levelname)s %(message)s").format(record)
        self.assertIn(C.GREY, output)

    def test_info_level_gets_blue(self):
        """INFO records have the BLUE color code injected into levelname."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("hello", level=logging.INFO)
        output = Formatter("%(levelname)s %(message)s").format(record)
        self.assertIn(C.BLUE, output)

    def test_warning_level_gets_yellow(self):
        """WARNING records have the YELLOW color code injected into levelname."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("hello", level=logging.WARNING)
        output = Formatter("%(levelname)s %(message)s").format(record)
        self.assertIn(C.YELLOW, output)

    def test_error_level_gets_red(self):
        """ERROR records have the RED color code injected into levelname."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("hello", level=logging.ERROR)
        output = Formatter("%(levelname)s %(message)s").format(record)
        self.assertIn(C.RED, output)

    def test_critical_level_gets_bold_and_red(self):
        """CRITICAL records have both BOLD and RED injected into levelname."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("hello", level=logging.CRITICAL)
        output = Formatter("%(levelname)s %(message)s").format(record)
        self.assertIn(C.BOLD, output)
        self.assertIn(C.RED, output)

    # ------------------------------------------------------------------ #
    # Message-specific colorization                                        #
    # ------------------------------------------------------------------ #

    def test_monitoring_cycle_gets_magenta_bold(self):
        """Messages containing 'Monitoring Cycle' are wrapped in MAGENTA+BOLD."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("Monitoring Cycle 42")
        output = Formatter("%(message)s").format(record)
        self.assertIn(C.MAGENTA, output)
        self.assertIn(C.BOLD, output)

    def test_waiting_message_gets_grey(self):
        """Waiting countdown messages are dimmed with GREY."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("Waiting 300 seconds until next check")
        output = Formatter("%(message)s").format(record)
        self.assertIn(C.GREY, output)

    def test_analysis_complete_gets_green(self):
        """'Analysis complete' messages are highlighted in GREEN."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("Analysis complete: score=25.0, risk=LOW")
        output = Formatter("%(message)s").format(record)
        self.assertIn(C.GREEN, output)

    def test_unmatched_message_not_special_colored(self):
        """Ordinary messages are not wrapped with MAGENTA or GREEN."""
        Formatter, C = self._reload_with_tty()
        record = self._make_record("Processing email from user@example.com")
        output = Formatter("%(message)s").format(record)
        # Level colorization (BLUE for INFO) may be present, but the
        # special message-wrapping colors (MAGENTA, GREEN) must not be.
        self.assertNotIn(C.MAGENTA, output)
        self.assertNotIn(C.GREEN, output)

    def test_waiting_without_seconds_phrase_not_dimmed(self):
        """'Waiting' alone (without 'seconds until next check') is not dimmed."""
        Formatter, C = self._reload_with_tty()
        # Use WARNING level so YELLOW appears instead of GREY (INFO level uses BLUE).
        # This lets us assert that GREY is absent from the output.
        record = self._make_record("Waiting for lock", level=logging.WARNING)
        output = Formatter("%(levelname)s %(message)s").format(record)
        self.assertNotIn(C.GREY, output)

    # ------------------------------------------------------------------ #
    # copy.copy guard — original record must not be mutated               #
    # ------------------------------------------------------------------ #

    def test_format_does_not_mutate_original_record(self):
        """format() must not modify the caller's LogRecord.

        SECURITY STORY: Multiple handlers (console, file, webhook) may
        process the same record. If the console handler injects ANSI codes
        into the shared record object, the file / webhook handler would log
        raw escape sequences, corrupting structured log output and potentially
        breaking downstream log-parsing tools.
        """
        fmt = logging_utils.ColoredFormatter()
        original_msg = "Monitoring Cycle 1"
        record = self._make_record(original_msg)
        original_levelname = record.levelname

        fmt.format(record)

        # The original record must retain its pre-format values.
        self.assertEqual(record.msg, original_msg)
        self.assertEqual(record.levelname, original_levelname)

    def test_format_does_not_mutate_second_reference(self):
        """Two handles referencing the same record are independently preserved."""
        fmt = logging_utils.ColoredFormatter()
        msg = "Analysis complete: score=0"
        record = self._make_record(msg)
        record_ref = record  # second reference to the *same* object

        fmt.format(record)

        self.assertEqual(record_ref.msg, msg)

    # ------------------------------------------------------------------ #
    # Edge cases                                                           #
    # ------------------------------------------------------------------ #

    def test_non_string_message_does_not_raise(self):
        """Non-string msg values (e.g. dicts, exceptions) are handled safely."""
        fmt = logging_utils.ColoredFormatter()
        record = self._make_record({"key": "value"})
        # Should not raise; result must be a string.
        result = fmt.format(record)
        self.assertIsInstance(result, str)

    def test_format_returns_string(self):
        """format() always returns a string regardless of input."""
        fmt = logging_utils.ColoredFormatter()
        for msg in ("normal message", "Monitoring Cycle 1", 42, None):
            record = self._make_record(msg)
            result = fmt.format(record)
            self.assertIsInstance(result, str)

    def test_level_colors_dict_covers_standard_levels(self):
        """LEVEL_COLORS must map all five standard logging levels."""
        expected_levels = {
            logging.DEBUG,
            logging.INFO,
            logging.WARNING,
            logging.ERROR,
            logging.CRITICAL,
        }
        self.assertEqual(
            set(logging_utils.ColoredFormatter.LEVEL_COLORS.keys()),
            expected_levels,
        )


if __name__ == "__main__":
    unittest.main()
