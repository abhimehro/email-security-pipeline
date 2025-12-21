
import unittest
import logging
from src.main import ColorFormatter
from src.utils.colors import Colors

class TestColorFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = ColorFormatter()

    def test_format_debug(self):
        record = logging.LogRecord(
            name="test", level=logging.DEBUG, pathname="test.py", lineno=1,
            msg="debug message", args=(), exc_info=None
        )
        formatted = self.formatter.format(record)

        # Check level name color
        self.assertIn(f"{Colors.GREY}DEBUG{Colors.RESET}", formatted)
        # Check message is NOT colored (only for ERROR+)
        self.assertIn("debug message", formatted)
        self.assertNotIn(f"{Colors.GREY}debug message", formatted)

    def test_format_info(self):
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="test.py", lineno=1,
            msg="info message", args=(), exc_info=None
        )
        formatted = self.formatter.format(record)

        # Check level name color
        self.assertIn(f"{Colors.GREEN}INFO{Colors.RESET}", formatted)
        # Check message is NOT colored
        self.assertIn("info message", formatted)

    def test_format_warning(self):
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="test.py", lineno=1,
            msg="warning message", args=(), exc_info=None
        )
        formatted = self.formatter.format(record)

        # Check level name color
        self.assertIn(f"{Colors.YELLOW}WARNING{Colors.RESET}", formatted)
        # Check message is NOT colored
        self.assertIn("warning message", formatted)

    def test_format_error(self):
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="test.py", lineno=1,
            msg="error message", args=(), exc_info=None
        )
        formatted = self.formatter.format(record)

        # Check level name color
        self.assertIn(f"{Colors.RED}ERROR{Colors.RESET}", formatted)
        # Check message IS colored
        self.assertIn(f"{Colors.RED}error message{Colors.RESET}", formatted)

    def test_format_critical(self):
        record = logging.LogRecord(
            name="test", level=logging.CRITICAL, pathname="test.py", lineno=1,
            msg="critical message", args=(), exc_info=None
        )
        formatted = self.formatter.format(record)

        # Check level name color
        self.assertIn(f"{Colors.MAGENTA}{Colors.BOLD}CRITICAL{Colors.RESET}", formatted)
        # Check message IS colored (uses same color as level)
        self.assertIn(f"{Colors.MAGENTA}{Colors.BOLD}critical message{Colors.RESET}", formatted)

    def test_record_not_modified(self):
        """Ensure the original record is not modified"""
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="test.py", lineno=1,
            msg="original message", args=(), exc_info=None
        )
        original_levelname = record.levelname
        original_msg = record.msg

        self.formatter.format(record)

        self.assertEqual(record.levelname, original_levelname)
        self.assertEqual(record.msg, original_msg)

if __name__ == '__main__':
    unittest.main()
