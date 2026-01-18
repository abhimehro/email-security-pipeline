import logging
import copy
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
        logging.CRITICAL: Colors.BOLD + Colors.RED
    }

    def format(self, record):
        # Create a copy of the record to avoid side effects on other handlers
        # (e.g., file logging shouldn't have ANSI codes)
        record = copy.copy(record)

        # Colorize level name
        color = self.LEVEL_COLORS.get(record.levelno, Colors.RESET)
        record.levelname = f"{color}{record.levelname}{Colors.RESET}"

        # UX Enhancement: Highlight specific operational messages
        if isinstance(record.msg, str):
            if "Monitoring Cycle" in record.msg:
                # Highlight the cycle start
                record.msg = f"{Colors.MAGENTA}{Colors.BOLD}{record.msg}{Colors.RESET}"
            elif "Waiting" in record.msg and "seconds until next check" in record.msg:
                # Dim the waiting message to reduce visual noise
                record.msg = f"{Colors.GREY}{record.msg}{Colors.RESET}"
            elif "Analysis complete" in record.msg:
                # Highlight success
                record.msg = f"{Colors.GREEN}{record.msg}{Colors.RESET}"

        return super().format(record)
