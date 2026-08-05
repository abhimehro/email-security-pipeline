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

    def _colorize_analysis_complete(self, msg: str) -> str:
        """Colorizes 'Analysis complete' messages based on risk level."""
        if "risk=HIGH" in msg:
            return Colors.colorize(msg, Colors.RED)
        if "risk=MEDIUM" in msg:
            return Colors.colorize(msg, Colors.YELLOW)
        return Colors.colorize(msg, Colors.GREEN)

    def _colorize_operational_message(self, msg: str) -> str:
        """Applies dynamic color highlights or dims to specific operational messages."""
        if "Monitoring Cycle" in msg:
            return Colors.colorize(msg, Colors.MAGENTA + Colors.BOLD)
        if "Waiting" in msg and "seconds until next check" in msg:
            return Colors.colorize(msg, Colors.GREY)
        if "No new emails to analyze" in msg:
            return Colors.colorize(msg, Colors.GREY)
        if "Analysis complete" in msg:
            return self._colorize_analysis_complete(msg)
        return msg

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
            record.msg = self._colorize_operational_message(record.msg)

        return super().format(record)
