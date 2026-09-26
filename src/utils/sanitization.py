"""
Sanitization Utility Module
Provides functions to sanitize inputs for safe logging and display.
"""

import re
import unicodedata

# Pre-compile regex for performance
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Pre-compile whitespace translation table for performance
_WHITESPACE_TRANS = str.maketrans("\n\r\t", "   ")

# Unicode categories to exclude from logging
# Cc: Control (including ASCII 0-31, 127, 0x80-0x9F)
# Cf: Format (including BiDi controls, Zero Width Space, Soft Hyphen)
# Cs: Surrogates
# Co: Private Use
# Cn: Unassigned
# Zl: Line Separator
# Zp: Paragraph Separator
EXCLUDED_LOGGING_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _is_allowed_char(ch: str) -> bool:
    """Check if a character is allowed in sanitized output."""
    if ch.isprintable():
        return True
    if ch == "\t":
        return True
    if unicodedata.category(ch) == "Zs":
        return True
    return False


class _LazyTranslateDict(dict):
    """
    Lazy-evaluating translation dictionary for str.translate().
    Computes character mappings on first encounter to avoid the
    massive memory and time overhead of pre-computing the full
    translation table for all 1.1 million Unicode characters.
    """

    def __missing__(self, key: int):
        ch = chr(key)
        if _is_allowed_char(ch):
            self[key] = key
            return key
        self[key] = None
        return None


_TRANSLATOR = _LazyTranslateDict()


def _truncate_text(text: str, max_length: int) -> str:
    """Truncate text to max_length to prevent log flooding."""
    if max_length <= 0:
        return "..."
    if len(text) > max_length:
        return text[:max_length] + "..."
    return text


def _sanitize_complex_log_text(text: str) -> str:
    """Apply normalization, CRLF escaping, ANSI removal, and character translation."""
    if not text.isascii():
        text = unicodedata.normalize("NFKC", text)

    text = text.replace("\n", "\\n").replace("\r", "\\r")

    if "\x1b" in text:
        text = ANSI_ESCAPE_PATTERN.sub("", text)

    return text.translate(_TRANSLATOR)


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

    # Fast-path optimization: Clean ASCII printable strings (the vast majority of log messages)
    # bypass NFKC normalization, CRLF/ANSI regex checks, and translation dictionary lookups.
    if text.isascii() and text.isprintable():
        return _truncate_text(text, max_length)

    text = _sanitize_complex_log_text(text)
    return _truncate_text(text, max_length)


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

    # Optimization: For clean strings not starting with whitespace,
    # inspect the first character directly to avoid lstrip() string allocation.
    first_char = text[0]
    if not first_char.isspace():
        if first_char in ("=", "+", "-", "@", "%", "|"):
            return "'" + text
        return text

    # Dangerous characters that can trigger formulas at the start of a cell
    # Note: We check the original string for TAB/CR at the start,
    # as lstrip() removes them.
    # Added '%' to prevent DDE injection in older spreadsheet software
    dangerous_chars = ("=", "+", "-", "@", "%")

    # Check if the string starts with characters that trigger formulas
    # Note: We must check after stripping whitespace because "  =1+1" can also be dangerous.
    stripped = text.lstrip()

    if stripped.startswith(dangerous_chars):
        return "'" + text

    # Also check for pipe at the start, which can be problematic in some CSV delimiters
    if stripped.startswith("|"):
        return "'" + text

    # Check for control characters at the very start (tab, carriage return)
    # which might not be caught by stripped check if they ARE the whitespace
    if text.startswith(("\t", "\r")):
        return "'" + text

    return text


def redact_email(email: str) -> str:
    """
    Redact email address for logging, keeping only the domain or partial info.
    Example: 'user@example.com' -> 'u***@example.com'.

    Args:
        email: The email address to redact.

    Returns:
        Redacted email string.

    """
    if not email or "@" not in email:
        return email

    try:
        user, domain = email.split("@", 1)
        if len(user) == 0:
            redacted_user = "***"
        elif len(user) <= 1:
            redacted_user = "*" * len(user)
        else:
            redacted_user = user[0] + "*" * (len(user) - 1)

        return sanitize_for_logging(f"{redacted_user}@{domain}")
    except Exception:
        # Fallback if splitting fails (unlikely given check above)
        return sanitize_for_logging(email)
