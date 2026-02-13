"""
ANSI Color codes for console output formatting.
Used to improve UX of the CLI and logs without adding external dependencies.
"""
import os
import sys

class Colors:
    """ANSI color codes with support for NO_COLOR and TTY detection"""

    # Check if colors should be enabled
    # 1. NO_COLOR env var (standard: https://no-color.org/)
    # 2. Not a TTY (piped output)
    _no_color = os.environ.get("NO_COLOR")
    _is_tty = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False

    # Logic: Enable if TTY and NO_COLOR is not set
    ENABLED = _is_tty and not _no_color

    RESET = "\033[0m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""

    # Foreground colors
    RED = "\033[91m" if ENABLED else ""
    GREEN = "\033[92m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    BLUE = "\033[94m" if ENABLED else ""
    MAGENTA = "\033[95m" if ENABLED else ""
    CYAN = "\033[96m" if ENABLED else ""
    WHITE = "\033[97m" if ENABLED else ""
    GREY = "\033[90m" if ENABLED else ""

    @classmethod
    def colorize(cls, text: str, color_code: str) -> str:
        """Wrap text in color codes if enabled"""
        if not cls.ENABLED:
            return text
        return f"{color_code}{text}{cls.RESET}"

    @classmethod
    def get_risk_color(cls, risk_level: str) -> str:
        """Get color code for a risk level"""
        if not cls.ENABLED:
            return ""

        level = risk_level.lower()
        if level == "high":
            return cls.RED
        elif level == "medium":
            return cls.YELLOW
        elif level == "low":
            return cls.GREEN
        return cls.WHITE

    @staticmethod
    def get_risk_symbol(risk_level: str) -> str:
        """Get emoji symbol for a risk level"""
        # Emojis are Unicode characters, not ANSI codes, so they are generally safe
        # unless specifically requested to be ASCII-only.
        # However, some non-TTY environments (like simple log files) might not handle emojis well.
        # For now, we keep emojis as they add significant value even in some non-color terminals.
        level = risk_level.lower()
        symbols = {
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }
        return symbols.get(level, "⚪")
