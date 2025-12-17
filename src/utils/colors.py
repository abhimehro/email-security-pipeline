"""
ANSI Color codes for console output formatting
"""

class Colors:
    """ANSI color codes and helper methods"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    # Text Colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Background Colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """Wrap text in color codes"""
        return f"{color}{text}{cls.RESET}"

    @classmethod
    def header(cls, text: str) -> str:
        """Format as a header (Bold Cyan)"""
        return f"{cls.BOLD}{cls.CYAN}{text}{cls.RESET}"

    @classmethod
    def warning(cls, text: str) -> str:
        """Format as a warning (Yellow)"""
        return f"{cls.YELLOW}{text}{cls.RESET}"

    @classmethod
    def error(cls, text: str) -> str:
        """Format as an error (Red)"""
        return f"{cls.RED}{text}{cls.RESET}"

    @classmethod
    def success(cls, text: str) -> str:
        """Format as success (Green)"""
        return f"{cls.GREEN}{text}{cls.RESET}"

    @classmethod
    def get_risk_color(cls, risk_level: str) -> str:
        """Get color code based on risk level"""
        level = risk_level.lower()
        if level == "high":
            return cls.RED
        elif level == "medium":
            return cls.YELLOW
        elif level == "low":
            return cls.GREEN
        return cls.WHITE
