import logging
import re
from src.utils.colors import Colors

class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored log output"""

    def format(self, record):
        # Save original levelname to restore later
        original_levelname = record.levelname

        # Colorize level name
        if record.levelno >= logging.CRITICAL:
            record.levelname = Colors.colorize(record.levelname, Colors.RED + Colors.BOLD)
        elif record.levelno >= logging.ERROR:
            record.levelname = Colors.colorize(record.levelname, Colors.RED)
        elif record.levelno >= logging.WARNING:
            record.levelname = Colors.colorize(record.levelname, Colors.YELLOW)
        elif record.levelno >= logging.INFO:
            record.levelname = Colors.colorize(record.levelname, Colors.GREEN)
        elif record.levelno >= logging.DEBUG:
            record.levelname = Colors.colorize(record.levelname, Colors.BLUE)

        # Format the message
        result = super().format(record)

        # Restore original levelname
        record.levelname = original_levelname
        return result


class StripAnsiFormatter(logging.Formatter):
    """Formatter that strips ANSI color codes for file logging"""
    ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def format(self, record):
        message = super().format(record)
        return self.ANSI_ESCAPE.sub('', message)
