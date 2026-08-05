import copy
import logging

from src.utils.colors import Colors


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter to add colors to log levels and specific messages.
    Improves CLI UX by highlighting key events and dimming repetitive ones.
    """

    LEVEL_COLORS = {
        logging.DEBUG: Colors.GREY,
        logging.INFO: Colors.BLUE,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BOLD + Colors.RED,
    }

    def format(self, record):
        # Create a copy of the record to avoid side effects on other handlers
        # (e.g., file logging shouldn't have ANSI codes)
        record = copy.copy(record)

        # Colorize level name and pad it to ensure vertical alignment of messages
        color = self.LEVEL_COLORS.get(record.levelno, "")
        padded_level = record.levelname.ljust(8)
        record.levelname = (
            Colors.colorize(padded_level, color) if color else padded_level
        )

        # UX Enhancement: Highlight specific operational messages
        if isinstance(record.msg, str):
            record.msg = self._colorize_message(str(record.msg))

        return super().format(record)

    def _colorize_message(self, msg_str: str) -> str:
        """Helper to apply UX highlighting to specific log messages."""
        if "Monitoring Cycle" in msg_str:
            # Highlight the cycle start
            return Colors.colorize(msg_str, Colors.MAGENTA + Colors.BOLD)

        if "Waiting" in msg_str and "seconds until next check" in msg_str:
            # Dim the waiting message to reduce visual noise
            return Colors.colorize(msg_str, Colors.GREY)

        if "No new emails to analyze" in msg_str:
            # Dim the repetitive no emails message to reduce visual noise
            return Colors.colorize(msg_str, Colors.GREY)

        if "Analysis complete" in msg_str:
            # Highlight based on risk
            if "risk=HIGH" in msg_str:
                return Colors.colorize(msg_str, Colors.RED)
            if "risk=MEDIUM" in msg_str:
                return Colors.colorize(msg_str, Colors.YELLOW)
            return Colors.colorize(msg_str, Colors.GREEN)

        return msg_str
