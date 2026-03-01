import unittest
from unittest.mock import patch, MagicMock
import sys
from io import StringIO
from src.utils.ui import Spinner
from src.utils.colors import Colors

class TestSpinner(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_success_persist(self, mock_stdout):
        # We need to mock isatty to be True for Spinner to activate
        mock_stdout.isatty = MagicMock(return_value=True)

        # Test default persist=True
        with Spinner("Testing Success"):
            pass

        output = mock_stdout.getvalue()
        # Verify checkmark and message are present. We mock isatty() to True above,
        # so Colors.ENABLED should be True and the spinner should use colored output.
        self.assertIn("✔ Testing Success", output)
        self.assertIn("Testing Success", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_success_no_persist(self, mock_stdout):
        mock_stdout.isatty = MagicMock(return_value=True)

        # Test persist=False
        with Spinner("Testing No Persist", persist=False):
            pass

        output = mock_stdout.getvalue()
        # Verify checkmark is NOT present
        self.assertNotIn("✔ Testing No Persist", output)
        # It should clear the line
        self.assertIn("\r\033[K", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_failure(self, mock_stdout):
        mock_stdout.isatty = MagicMock(return_value=True)

        try:
            with Spinner("Testing Failure"):
                raise ValueError("Oops")
        except ValueError:
            pass

        output = mock_stdout.getvalue()
        # Verify cross is present
        self.assertIn("✘ Testing Failure", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_non_tty_basic_output(self, mock_stdout):
        # Simulate a non-TTY environment (e.g., CI logs, redirected output)
        mock_stdout.isatty = MagicMock(return_value=False)

        with Spinner("Testing non TTY basic"):
            # No exception: spinner should complete successfully
            pass

        output = mock_stdout.getvalue()
        # Verify that the message itself was printed in non-TTY mode
        self.assertIn("Testing non TTY basic", output)
        # In non-TTY mode we should not rely on TTY-specific clear sequences
        self.assertNotIn("\r\033[K", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_success_persist_non_tty(self, mock_stdout):
        # Non-TTY with default persist=True should still print a success message
        mock_stdout.isatty = MagicMock(return_value=False)

        with Spinner("Testing non TTY persist"):
            pass

        output = mock_stdout.getvalue()
        # Verify checkmark success line is present even when not in a TTY
        self.assertIn("✔ Testing non TTY persist", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_success_no_persist_non_tty(self, mock_stdout):
        # Non-TTY with persist=False should not print a success line
        mock_stdout.isatty = MagicMock(return_value=False)

        with Spinner("Testing non TTY no persist", persist=False):
            pass

        output = mock_stdout.getvalue()
        # Verify checkmark success line is NOT present
        self.assertNotIn("✔ Testing non TTY no persist", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_failure_non_tty(self, mock_stdout):
        # Non-TTY failure should still emit a clear failure message
        mock_stdout.isatty = MagicMock(return_value=False)

        try:
            with Spinner("Testing non TTY failure"):
                raise ValueError("Oops")
        except ValueError:
            # Swallow the error so we can assert on the output
            pass

        output = mock_stdout.getvalue()
        # Verify failure cross message is present in non-TTY mode
        self.assertIn("✘ Testing non TTY failure", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_custom_success(self, mock_stdout):
        mock_stdout.isatty = MagicMock(return_value=True)

        with Spinner("Checking...", persist=False) as s:
            s.success("Done!")

        output = mock_stdout.getvalue()
        # Verify custom success message overrides persist=False
        self.assertIn("✔ Done!", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_custom_failure(self, mock_stdout):
        mock_stdout.isatty = MagicMock(return_value=True)

        try:
            with Spinner("Checking...") as s:
                s.fail("Failed!")
                raise ValueError("Oops")
        except ValueError:
            pass

        output = mock_stdout.getvalue()
        # Verify custom failure message is used
        self.assertIn("✘ Failed!", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_custom_success_non_tty(self, mock_stdout):
        mock_stdout.isatty = MagicMock(return_value=False)

        with Spinner("Checking...", persist=False) as s:
            s.success("Custom Done!")

        output = mock_stdout.getvalue()
        # Verify custom success message overrides persist=False in non-TTY mode
        self.assertIn("✔ Custom Done!", output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_spinner_custom_failure_non_tty(self, mock_stdout):
        mock_stdout.isatty = MagicMock(return_value=False)

        try:
            with Spinner("Checking...") as s:
                s.fail("Custom Failed!")
                raise ValueError("Oops")
        except ValueError:
            pass

        output = mock_stdout.getvalue()
        # Verify custom failure message is printed in non-TTY mode
        self.assertIn("✘ Custom Failed!", output)
