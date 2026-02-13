"""Tests for Colors utility class."""

import unittest
import sys
import os
import importlib
from unittest.mock import patch, MagicMock
from src.utils import colors


class TestColors(unittest.TestCase):
    """Test color utility methods."""

    def tearDown(self):
        # Ensure we restore the module to a usable state after tests
        # This is critical because reload modifies the global module object
        importlib.reload(colors)

    def _reload_colors(self, mock_tty=True, mock_no_color=None):
        """Helper to reload Colors module with specific environment"""

        # Prepare mock stdout
        mock_stdout = MagicMock()
        mock_stdout.isatty.return_value = mock_tty

        with patch('sys.stdout', mock_stdout):
            # Manage environment variable
            # We use patch.dict to restore environment after block
            with patch.dict(os.environ):
                if mock_no_color is not None:
                    os.environ['NO_COLOR'] = mock_no_color
                elif 'NO_COLOR' in os.environ:
                    del os.environ['NO_COLOR']

                # Reload module
                importlib.reload(colors)
                return colors.Colors

    def test_get_risk_symbol_high(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_symbol("high"), "🔴")

    def test_get_risk_symbol_medium(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_symbol("medium"), "🟡")

    def test_get_risk_symbol_low(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_symbol("low"), "🟢")

    def test_get_risk_symbol_unknown(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_symbol("unknown"), "⚪")

    def test_get_risk_symbol_case_insensitive(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_symbol("HIGH"), "🔴")
        self.assertEqual(Cls.get_risk_symbol("Medium"), "🟡")
        self.assertEqual(Cls.get_risk_symbol("Low"), "🟢")

    def test_get_risk_color_high(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_color("high"), Cls.RED)
        self.assertNotEqual(Cls.RED, "")

    def test_get_risk_color_medium(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_color("medium"), Cls.YELLOW)

    def test_get_risk_color_low(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_color("low"), Cls.GREEN)

    def test_get_risk_color_unknown(self):
        Cls = self._reload_colors(mock_tty=True)
        self.assertEqual(Cls.get_risk_color("unknown"), Cls.WHITE)

    def test_colorize(self):
        Cls = self._reload_colors(mock_tty=True)
        result = Cls.colorize("test", Cls.RED)
        self.assertEqual(result, f"{Cls.RED}test{Cls.RESET}")

    def test_no_color_env(self):
        """Test that NO_COLOR disables colors"""
        Cls = self._reload_colors(mock_tty=True, mock_no_color="1")
        self.assertFalse(Cls.ENABLED)
        self.assertEqual(Cls.RED, "")
        self.assertEqual(Cls.colorize("test", "\033[91m"), "test")
        self.assertEqual(Cls.get_risk_color("high"), "")

    def test_non_tty(self):
        """Test that non-TTY disables colors"""
        Cls = self._reload_colors(mock_tty=False)
        self.assertFalse(Cls.ENABLED)
        self.assertEqual(Cls.RED, "")
        self.assertEqual(Cls.colorize("test", "\033[91m"), "test")


if __name__ == "__main__":
    unittest.main()
