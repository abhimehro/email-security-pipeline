"""
Pattern Compiler Utility

Centralizes regex pattern compilation with consistent flags and ReDoS safety checks.

SECURITY STORY: Protects against ReDoS (Regular Expression Denial of Service) attacks
where an attacker supplies crafted input that triggers catastrophic backtracking in
regex patterns.  By centralizing all pattern compilation here, every analyzer in the
pipeline automatically receives consistent safety validation and flag handling rather
than having each module roll its own compilation logic.

MAINTENANCE WISDOM: When adding new patterns to any analyzer, compile them through
these helpers so that the ReDoS guard and flag defaults are always applied uniformly.
"""

import re
from typing import Dict, List, Tuple

# Known ReDoS signatures — nested or repeated quantifiers on unbounded character
# classes are the most common source of catastrophic backtracking.
_REDOS_SIGNATURES: List[str] = [
    r"(\w+)*",
    r"(\d+)+",
    r"(\s+)*",
    r"(a+)+",
    r"([a-zA-Z]+)*",
]


def check_redos_safety(patterns: List[str]) -> None:
    """
    Raise ValueError if any pattern contains a known ReDoS signature.

    SECURITY STORY: This is a lightweight static check, not a full ReDoS
    prover.  It catches the most common catastrophic-backtracking forms so
    that unsafe patterns are rejected at startup rather than discovered under
    production load.

    Note: Detection uses substring matching against a fixed signature list.
    This is deliberately conservative — a signature substring anywhere in a
    pattern string will trigger the check.  The trade-off is simplicity and
    zero false negatives for the known-dangerous forms at the cost of rare
    false positives for patterns that contain the substring in a safe context
    (e.g., inside a character class).  For the email-analysis patterns in
    this codebase every flagged occurrence is genuinely dangerous.

    Args:
        patterns: List of regex pattern strings to inspect.

    Raises:
        ValueError: If any pattern contains a known ReDoS signature.
    """
    for pattern in patterns:
        for unsafe in _REDOS_SIGNATURES:
            if unsafe in pattern:
                raise ValueError(f"Potential ReDoS in pattern: {pattern!r}")


def compile_patterns(
    patterns: List[str],
    flags: int = re.I,
    validate_redos: bool = True,
) -> re.Pattern:
    """
    Compile a list of regex pattern strings into a single combined OR pattern.

    Each pattern is wrapped in a non-capturing group before joining so that
    top-level alternation precedence is preserved correctly regardless of
    what operators the individual patterns contain.

    PATTERN RECOGNITION: This replaces the common idiom
    ``re.compile("|".join(patterns), flags)`` with proper grouping and
    optional safety validation.

    Args:
        patterns: List of regex pattern strings.
        flags: Regex compilation flags (default: ``re.I`` for case-insensitive).
        validate_redos: If ``True``, run ``_check_redos_safety`` before compiling.

    Returns:
        A compiled :class:`re.Pattern` that matches any of the supplied patterns.
    """
    if validate_redos:
        check_redos_safety(patterns)
    parts = [f"(?:{p})" for p in patterns]
    return re.compile("|".join(parts), flags)


def compile_named_group_pattern(
    patterns: List[str],
    flags: int = re.I,
    group_prefix: str = "p",
    validate_redos: bool = True,
) -> Tuple[re.Pattern, Dict[str, str]]:
    """
    Compile pattern strings into a combined OR regex with named capture groups.

    Each pattern is assigned a unique named group so that match objects can be
    attributed back to the originating pattern string via ``match.lastgroup``.

    PATTERN RECOGNITION: This replaces verbose class-level loop code that
    manually built named groups, giving the same result with a clear API.

    Args:
        patterns: List of regex pattern strings.
        flags: Regex compilation flags (default: ``re.I``).
        group_prefix: Prefix for generated group names.
                      E.g. ``"spam_kw"`` → ``"spam_kw_0"``, ``"spam_kw_1"``, …
        validate_redos: If ``True``, run ``check_redos_safety`` before compiling.

    Returns:
        A tuple ``(compiled_pattern, group_map)`` where *group_map* maps each
        generated group name to its original pattern string.
    """
    if validate_redos:
        check_redos_safety(patterns)
    parts: List[str] = []
    group_map: Dict[str, str] = {}
    for i, p in enumerate(patterns):
        name = f"{group_prefix}_{i}"
        parts.append(f"(?P<{name}>{p})")
        group_map[name] = p
    return re.compile("|".join(parts), flags), group_map
