import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

from src.utils.ui import CountdownTimer, Spinner
from src.utils.colors import Colors


class TestUI(unittest.TestCase):
    @patch("sys.stdout", new_callable=StringIO)
    @patch("time.sleep")
    def test_countdown_timer_progress_loop(self, mock_sleep, mock_stdout):
        """Test the progress bar loop and time string formatting."""
        mock_stdout.isatty = MagicMock(return_value=True)
        # Test less than a minute
        timer = CountdownTimer(duration=2, message="Testing", interval=1.0)
        timer.start()
        output = mock_stdout.getvalue()
        self.assertIn("2s", output)
        self.assertIn("1s", output)
        self.assertIn("█", output)

    @patch("sys.stdout", new_callable=StringIO)
    @patch("time.sleep")
    def test_countdown_timer_minutes_format(self, mock_sleep, mock_stdout):
        """Test formatting of remaining time > 60s."""
        mock_stdout.isatty = MagicMock(return_value=True)
        # Use interval > duration to exit the loop after 1 iteration
        timer = CountdownTimer(duration=65, message="Testing", interval=70.0)
        timer.start()
        output = mock_stdout.getvalue()
        self.assertIn("1:05", output)

    @patch("sys.stdout")
    @patch("threading.Thread")
    @patch("time.sleep", side_effect=[KeyboardInterrupt, None])
    def test_spinner_start_tty_sleep_interrupt(
        self, mock_sleep, mock_thread, mock_stdout
    ):
        """Test that KeyboardInterrupt during initial sleep is caught and ignored."""
        spinner = Spinner("Testing")
        # _start_tty_spinner handles KeyboardInterrupt during time.sleep(0.1)
        spinner._start_tty_spinner("Testing...")
        # The thread should still be started
        mock_thread.assert_called_once()
        self.assertTrue(spinner.busy)

    def test_spinner_get_color_for_unknown_symbol(self):
        """Test fallback color for unknown symbols."""
        spinner = Spinner("Testing")
        color = spinner._get_color_for_symbol("?")
        self.assertEqual(color, Colors.WHITE)


if __name__ == "__main__":
    unittest.main()
