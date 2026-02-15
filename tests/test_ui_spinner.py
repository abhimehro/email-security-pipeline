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
        # Verify checkmark is present
        # Note: Colors might be empty strings if not a TTY, but we can check for the symbol
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
