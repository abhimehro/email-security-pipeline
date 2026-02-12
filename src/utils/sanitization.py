"""
Sanitization Utility Module
Provides functions to sanitize inputs for safe logging and display.
"""

import re
import unicodedata

# Pre-compile regex for performance
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Unicode categories to exclude from logging
# Cc: Control (including ASCII 0-31, 127, 0x80-0x9F)
# Cf: Format (including BiDi controls, Zero Width Space, Soft Hyphen)
# Cs: Surrogates
# Co: Private Use
# Cn: Unassigned
# Zl: Line Separator
# Zp: Paragraph Separator
EXCLUDED_LOGGING_CATEGORIES = {'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'}

def sanitize_for_logging(text: str, max_length: int = 255) -> str:
    """
    Sanitize text for safe logging to prevent Log Injection (CRLF),
    terminal manipulation, and obfuscation via BiDi/format characters.

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

    # 3. Remove ANSI escape sequences (for terminal colors/cursor movement)
    text = ANSI_ESCAPE_PATTERN.sub('', text)

    # 4. Remove control characters and dangerous format characters
    # We keep standard printable characters but remove controls and formatters
    # that could be used for obfuscation (like BiDi overrides).
    # We explicitly allow Tab as it is useful for formatting and harmless.
    text = "".join(
        ch for ch in text
        if ch == '\t' or unicodedata.category(ch) not in EXCLUDED_LOGGING_CATEGORIES
    )

    # 5. Truncate if necessary to prevent log flooding
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
    # Added '%' to prevent DDE injection in older spreadsheet software
    dangerous_chars = ('=', '+', '-', '@', '%')

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
