import logging
from .colors import Colors

class LogFormatter(logging.Formatter):
    """Custom formatter for colored console output"""

    FORMATS = {
        logging.DEBUG:    f"{Colors.GREY}%(asctime)s{Colors.RESET} - {Colors.CYAN}%(name)s{Colors.RESET} - {Colors.GREY}%(levelname)s{Colors.RESET} - %(message)s",
        logging.INFO:     f"{Colors.GREY}%(asctime)s{Colors.RESET} - {Colors.CYAN}%(name)s{Colors.RESET} - {Colors.GREEN}%(levelname)s{Colors.RESET} - %(message)s",
        logging.WARNING:  f"{Colors.GREY}%(asctime)s{Colors.RESET} - {Colors.CYAN}%(name)s{Colors.RESET} - {Colors.YELLOW}%(levelname)s{Colors.RESET} - %(message)s",
        logging.ERROR:    f"{Colors.GREY}%(asctime)s{Colors.RESET} - {Colors.CYAN}%(name)s{Colors.RESET} - {Colors.RED}%(levelname)s{Colors.RESET} - %(message)s",
        logging.CRITICAL: f"{Colors.GREY}%(asctime)s{Colors.RESET} - {Colors.CYAN}%(name)s{Colors.RESET} - {Colors.BOLD}{Colors.RED}%(levelname)s{Colors.RESET} - %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS[logging.INFO])
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)
