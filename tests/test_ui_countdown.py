"""
Unit tests for CountdownTimer in src/utils/ui.py.

Covers:
- Non-TTY path: start() sleeps for duration without writing to stdout
- stop() sets the internal _stop_event
- wait() static method: hint injection, idempotency guard, and TTY branching
"""

import unittest
from unittest.mock import patch, MagicMock
from io import StringIO

from src.utils.ui import CountdownTimer


class TestCountdownTimerNonTTY(unittest.TestCase):
    """Tests for CountdownTimer.start() in non-TTY (non-interactive) mode."""

    @patch("time.sleep")
    @patch("sys.stdout", new_callable=StringIO)
    def test_start_non_tty_sleeps_for_duration(self, mock_stdout, mock_sleep):
        """start() must call time.sleep(duration) exactly once in non-TTY mode."""
        mock_stdout.isatty = MagicMock(return_value=False)
        timer = CountdownTimer(duration=5, message="Waiting")
        timer.start()
        mock_sleep.assert_called_once_with(5)

    @patch("time.sleep")
    @patch("sys.stdout", new_callable=StringIO)
    def test_start_non_tty_writes_nothing(self, mock_stdout, mock_sleep):
        """start() must not write anything to stdout in non-TTY mode."""
        mock_stdout.isatty = MagicMock(return_value=False)
        timer = CountdownTimer(duration=3, message="Waiting")
        timer.start()
        self.assertEqual(mock_stdout.getvalue(), "")

    def test_stop_sets_event(self):
        """stop() must mark the internal _stop_event so the loop exits."""
        timer = CountdownTimer(duration=10)
        self.assertFalse(timer._stop_event.is_set())
        timer.stop()
        self.assertTrue(timer._stop_event.is_set())


class TestCountdownTimerWait(unittest.TestCase):
    """Tests for the CountdownTimer.wait() static convenience method."""

    @patch("src.utils.ui.CountdownTimer.start")
    @patch("sys.stdout", new_callable=StringIO)
    def test_wait_non_tty_no_hint(self, mock_stdout, mock_start):
        """wait() must NOT append the Ctrl+C hint when stdout is not a TTY."""
        mock_stdout.isatty = MagicMock(return_value=False)

        # Capture the message used to construct CountdownTimer inside wait().
        created_messages = []
        original_init = CountdownTimer.__init__

        def capturing_init(self_inner, duration, message="Waiting", interval=1.0):
            # Record the message so we can assert that the Ctrl+C hint is absent
            created_messages.append(message)
            # Delegate to the real __init__ to preserve original behavior
            original_init(self_inner, duration, message, interval)

        with patch.object(CountdownTimer, "__init__", capturing_init):
            CountdownTimer.wait(5, "Reconnecting")

        mock_start.assert_called_once()
        # Ensure we actually captured a constructed timer
        self.assertTrue(len(created_messages) > 0)
        # In non-TTY mode, wait() must NOT inject the Ctrl+C hint into the message
        self.assertNotIn("Press Ctrl+C to stop", created_messages[0])

    @patch("src.utils.ui.CountdownTimer.start")
    @patch("sys.stdout", new_callable=StringIO)
    def test_wait_tty_appends_hint(self, mock_stdout, mock_start):
        """wait() must append the Ctrl+C hint when stdout is a TTY."""
        mock_stdout.isatty = MagicMock(return_value=True)

        # Capture the CountdownTimer constructed inside wait().
        created_timers = []
        original_init = CountdownTimer.__init__

        def capturing_init(self_inner, duration, message="Waiting", interval=1.0):
            created_timers.append(message)
            original_init(self_inner, duration, message, interval)

        with patch.object(CountdownTimer, "__init__", capturing_init):
            CountdownTimer.wait(3, "Reconnecting")

        self.assertTrue(len(created_timers) > 0)
        self.assertIn("Press Ctrl+C to stop", created_timers[0])

    @patch("src.utils.ui.CountdownTimer.start")
    @patch("sys.stdout", new_callable=StringIO)
    def test_wait_tty_no_double_hint(self, mock_stdout, mock_start):
        """wait() must NOT duplicate the hint if it is already in the message."""
        mock_stdout.isatty = MagicMock(return_value=True)

        already_hinted = "Reconnecting (Press Ctrl+C to stop)"
        created_timers = []
        original_init = CountdownTimer.__init__

        def capturing_init(self_inner, duration, message="Waiting", interval=1.0):
            created_timers.append(message)
            original_init(self_inner, duration, message, interval)

        with patch.object(CountdownTimer, "__init__", capturing_init):
            CountdownTimer.wait(3, already_hinted)

        self.assertTrue(len(created_timers) > 0)
        msg = created_timers[0]
        # The hint phrase must appear exactly once
        self.assertEqual(msg.count("Press Ctrl+C to stop"), 1)

    @patch("src.utils.ui.CountdownTimer.start")
    @patch("sys.stdout", new_callable=StringIO)
    def test_wait_calls_start_once(self, mock_stdout, mock_start):
        """wait() must call start() exactly once regardless of TTY mode."""
        mock_stdout.isatty = MagicMock(return_value=False)
        CountdownTimer.wait(2, "Testing")
        mock_start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
