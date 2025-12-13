"""
ANSI Color Codes for Console Output
Simple utility to add color and style to terminal output without external dependencies.
"""

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def colorize(text: str, color: str) -> str:
        """
        Apply color to text.

        Args:
            text (str): Text to colorize.
            color (str): ANSI color code (e.g., Colors.RED, Colors.BLUE).

        Returns:
    def bold(text: str) -> str:
        """
        Apply bold style to text.

        Args:
            text (str): Text to make bold.

        Returns:
            str: Text wrapped with bold and reset codes.
        """
        return f"{Colors.BOLD}{text}{Colors.RESET}"

    @staticmethod
    def get_risk_color(level: str) -> str:
        """Get color for risk level"""
        level = level.lower()
        if level == "high":
            return Colors.RED
        elif level == "medium":
            return Colors.YELLOW
        elif level == "low":
            return Colors.GREEN
        return Colors.RESET
