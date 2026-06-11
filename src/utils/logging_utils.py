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
        record.levelname = Colors.colorize(padded_level, color) if color else padded_level

        # UX Enhancement: Highlight specific operational messages
        if isinstance(record.msg, str):
            if "Monitoring Cycle" in record.msg:
                # Highlight the cycle start
                record.msg = Colors.colorize(
                    str(record.msg), Colors.MAGENTA + Colors.BOLD
                )
            elif "Waiting" in record.msg and "seconds until next check" in record.msg:
                # Dim the waiting message to reduce visual noise
                record.msg = Colors.colorize(str(record.msg), Colors.GREY)
            elif "Analysis complete" in record.msg:
                # Highlight success
                record.msg = Colors.colorize(str(record.msg), Colors.GREEN)

        return super().format(record)
