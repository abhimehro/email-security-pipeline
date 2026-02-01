"""
Sanitization Utility Module
Provides functions to sanitize inputs for safe logging and display.
"""

import re
import unicodedata

# Pre-compile regex for performance
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
# Control characters to remove: 0-8, 11-12, 14-31, 127
# We keep \t (9), and \n (10) / \r (13) are handled by replacement
CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')


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

    # Optimization: Early truncation to avoid processing huge strings
    # We allow some buffer (4x) for expansion (e.g. unicode normalization or escaping)
    limit = max_length * 4
    if len(text) > limit:
        text = text[:limit]

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
    # Optimization: Use regex instead of list comprehension for performance
    text = CONTROL_CHARS_PATTERN.sub('', text)

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
