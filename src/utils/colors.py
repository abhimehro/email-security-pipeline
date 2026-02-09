"""
ANSI Color codes for console output formatting.
Used to improve UX of the CLI and logs without adding external dependencies.
"""

class Colors:
    """ANSI color codes"""
    RESET = "\033[0m"
    BOLD = "\033[1m"

    # Foreground colors
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"

    @classmethod
    def colorize(cls, text: str, color_code: str) -> str:
        """Wrap text in color codes"""
        return f"{color_code}{text}{cls.RESET}"

    @classmethod
    def get_risk_color(cls, risk_level: str) -> str:
        """Get color code for a risk level"""
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
        level = risk_level.lower()
        symbols = {
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }
        return symbols.get(level, "⚪")
