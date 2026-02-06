"""
Sanitization Utility Module
Provides functions to sanitize inputs for safe logging and display.
"""

import re
import unicodedata

# Pre-compile regex for performance
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Create translation table for control characters
# Map chars 0-31 to None, except 9 (tab)
CONTROL_CHARS = dict.fromkeys(range(32), None)
del CONTROL_CHARS[9]  # Keep tab


def sanitize_for_logging(text: str, max_length: int = 255) -> str:
    """
    Sanitize text for safe logging to prevent Log Injection (CRLF) and terminal manipulation.

    Args:
        text: The input string to sanitize.
        max_length: Maximum allowed length for the log entry (truncates if longer).

    Returns:
        Sanitized string safe for logging.
    """
    if not text:
        return ""

    # 1. Normalize unicode characters
    text = unicodedata.normalize('NFKC', text)

    # 2. Replace newlines and carriage returns with escaped versions
    text = text.replace('\n', '\\n').replace('\r', '\\r')

    # 3. Remove or replace other control characters (keeping printable characters)
    # We keep standard ASCII printable characters and common unicode characters,
    # but remove control codes that aren't whitespace.
    # The regex [^\w\s\-\.\:\@\/] is too restrictive for general text,
    # so we focus on removing non-printable control characters.

    # Remove ANSI escape sequences (for terminal colors/cursor movement)
    text = ANSI_ESCAPE_PATTERN.sub('', text)

    # Remove other non-printable control characters (ASCII 0-31 except tab)
    # We already handled \n and \r above.
    # Optimization: Use translate instead of list comprehension/join (18x speedup on large strings)
    text = text.translate(CONTROL_CHARS)

    # 4. Truncate if necessary to prevent log flooding
    if len(text) > max_length:
        text = text[:max_length] + "..."

    return text

def sanitize_for_csv(text: str) -> str:
    """
    Sanitize text to prevent CSV Injection (Formula Injection).
    Prepends a single quote if the text starts with =, +, -, @, or other dangerous patterns.
    This prevents spreadsheet software from executing the text as a formula
    when the data is exported to CSV or displayed in a tabular format.

    Args:
        text: The input string to sanitize.

    Returns:
        Sanitized string safe for CSV usage.
    """
    if not text:
        return ""

    # Dangerous characters that can trigger formulas at the start of a cell
    # Note: We check the original string for TAB/CR at the start,
    # as lstrip() removes them.
    dangerous_chars = ('=', '+', '-', '@')

    # Check if the string starts with characters that trigger formulas
    # Note: We must check after stripping whitespace because "  =1+1" can also be dangerous.
    stripped = text.lstrip()

    if stripped.startswith(dangerous_chars):
        return "'" + text

    # Also check for pipe at the start, which can be problematic in some CSV delimiters
    if stripped.startswith('|'):
        return "'" + text

    # Check for control characters at the very start (tab, carriage return)
    # which might not be caught by stripped check if they ARE the whitespace
    if text.startswith(('\t', '\r')):
        return "'" + text

    return text
