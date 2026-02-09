"""Tests for Colors utility class."""

import unittest
from src.utils.colors import Colors


class TestColors(unittest.TestCase):
    """Test color utility methods."""

    def test_get_risk_symbol_high(self):
        self.assertEqual(Colors.get_risk_symbol("high"), "🔴")

    def test_get_risk_symbol_medium(self):
        self.assertEqual(Colors.get_risk_symbol("medium"), "🟡")

    def test_get_risk_symbol_low(self):
        self.assertEqual(Colors.get_risk_symbol("low"), "🟢")

    def test_get_risk_symbol_unknown(self):
        self.assertEqual(Colors.get_risk_symbol("unknown"), "⚪")

    def test_get_risk_symbol_case_insensitive(self):
        self.assertEqual(Colors.get_risk_symbol("HIGH"), "🔴")
        self.assertEqual(Colors.get_risk_symbol("Medium"), "🟡")
        self.assertEqual(Colors.get_risk_symbol("Low"), "🟢")

    def test_get_risk_color_high(self):
        self.assertEqual(Colors.get_risk_color("high"), Colors.RED)

    def test_get_risk_color_medium(self):
        self.assertEqual(Colors.get_risk_color("medium"), Colors.YELLOW)

    def test_get_risk_color_low(self):
        self.assertEqual(Colors.get_risk_color("low"), Colors.GREEN)

    def test_get_risk_color_unknown(self):
        self.assertEqual(Colors.get_risk_color("unknown"), Colors.WHITE)

    def test_colorize(self):
        result = Colors.colorize("test", Colors.RED)
        self.assertEqual(result, f"{Colors.RED}test{Colors.RESET}")


if __name__ == "__main__":
    unittest.main()
