"""
Sanitization Utility Module
Provides functions to sanitize inputs for safe logging and display.
"""

import re
import unicodedata

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
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)

    # Remove other non-printable control characters (ASCII 0-31 except tab)
    # We already handled \n and \r above.
    text = "".join(ch for ch in text if ch == '\t' or ord(ch) >= 32)

    # 4. Truncate if necessary to prevent log flooding
    if len(text) > max_length:
        text = text[:max_length] + "..."

    return text
