import sys
from unittest import TestCase
from unittest.mock import patch, MagicMock
from src.utils.ui import CountdownTimer

class TestPaletteUI(TestCase):
    def test_countdown_timer_keyboard_interrupt_hint(self):
        # Verify the "Press Ctrl+C to stop" hint is added correctly.
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.isatty.return_value = True

            with patch('src.utils.ui.CountdownTimer') as mock_timer_cls:
                mock_timer = MagicMock()
                mock_timer_cls.return_value = mock_timer

                # Should append hint
                CountdownTimer.wait(1, "Testing")
                mock_timer_cls.assert_called_with(1, "Testing (Press Ctrl+C to stop)")

                # Should not append hint if already present
                CountdownTimer.wait(1, "Testing (Press Ctrl+C to stop)")
                mock_timer_cls.assert_called_with(1, "Testing (Press Ctrl+C to stop)")

    def test_countdown_cursor_hide_show_in_tty(self):
        """Test cursor is hidden and restored when isatty is True for CountdownTimer"""
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.isatty.return_value = True

            timer = CountdownTimer(duration=0, message="Test")
            timer.start()

            writes = "".join(call.args[0] for call in mock_stdout.write.mock_calls if call.args)
            self.assertIn("\033[?25l", writes)  # CURSOR_HIDE
            self.assertIn("\033[?25h", writes)  # CURSOR_SHOW

    def test_countdown_cursor_hide_show_not_in_non_tty(self):
        """Test cursor escape sequences are not written when isatty is False for CountdownTimer"""
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.isatty.return_value = False

            timer = CountdownTimer(duration=0, message="Test")
            timer.start()

            writes = "".join(call.args[0] for call in mock_stdout.write.mock_calls if call.args)
            self.assertNotIn("\033[?25l", writes)
            self.assertNotIn("\033[?25h", writes)
