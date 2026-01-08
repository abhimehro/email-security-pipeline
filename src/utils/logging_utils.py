"""
Logging utilities for the Email Security Pipeline.
Provides custom formatters for colored console output.
"""

import logging
from src.utils.colors import Colors


class ColorFormatter(logging.Formatter):
    """
    Custom logging formatter that adds colors to log levels and messages
    based on severity.
    """

    FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    def format(self, record):
        # Determine color based on log level
        if record.levelno == logging.DEBUG:
            level_color = Colors.GREY
            msg_color = Colors.GREY
        elif record.levelno == logging.INFO:
            level_color = Colors.GREEN
            msg_color = Colors.RESET
        elif record.levelno == logging.WARNING:
            level_color = Colors.YELLOW
            msg_color = Colors.YELLOW
        elif record.levelno == logging.ERROR:
            level_color = Colors.RED
            msg_color = Colors.RED
        elif record.levelno == logging.CRITICAL:
            level_color = Colors.BOLD + Colors.RED
            msg_color = Colors.BOLD + Colors.RED
        else:
            level_color = Colors.WHITE
            msg_color = Colors.RESET

        # Format the level name
        levelname = f"{level_color}{record.levelname}{Colors.RESET}"

        # Create a custom format string for this record
        # We want: Timestamp - Logger - [COLOR]Level[RESET] - [COLOR_IF_WARN/ERR]Message[RESET]

        # Note: We need to handle the message separately if we want to color it entirely
        # safely without modifying the record permanently for other handlers.

        # Construct the formatted message
        # We delegate to the parent class to handle date formatting and basic interpolation

        # But to insert colors, we can define a specific fmt string

        # If we use the standard format string, we can modify the levelname in the record temporarily

        original_levelname = record.levelname
        original_msg = record.msg

        record.levelname = levelname

        # For Warning/Error/Critical, we color the message too
        if record.levelno >= logging.WARNING:
             record.msg = f"{msg_color}{record.msg}{Colors.RESET}"
        elif record.levelno == logging.DEBUG:
             record.msg = f"{msg_color}{record.msg}{Colors.RESET}"

        # Use standard formatter logic
        formatter = logging.Formatter(self.FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
        result = formatter.format(record)

        # Restore record
        record.levelname = original_levelname
        record.msg = original_msg

        return result
