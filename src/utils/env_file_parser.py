"""Safely parse environment files without executing shell commands.

SECURITY: Never use shell ``source`` on env files (CWE-78). This module only
extracts validated KEY=VALUE assignments.
"""

from __future__ import annotations

import re
from pathlib import Path

_VALID_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TRAILING_COMMENT = re.compile(r"\s+#.*$")
_UNQUOTED_FORBIDDEN = re.compile(r"[\s;|&`$<>()\\]")
_COMMAND_SUBSTITUTION = re.compile(r"\$\(|`")


class EnvParseError(ValueError):
    """Raised when an env file contains unsafe or malformed content."""


def _validate_key(key: str, line_number: int) -> None:
    if not _VALID_KEY.fullmatch(key):
        raise EnvParseError(f"line {line_number}: invalid variable name {key!r}")


def _reject_command_substitution(value: str, line_number: int) -> None:
    if _COMMAND_SUBSTITUTION.search(value):
        raise EnvParseError(
            f"line {line_number}: command substitution is not allowed"
        )


def _parse_quoted_value(value: str, line_number: int) -> str:
    quote = value[0]
    if len(value) < 2 or value[-1] != quote:
        raise EnvParseError(f"line {line_number}: unterminated quoted value")
    parsed = value[1:-1]
    _reject_command_substitution(parsed, line_number)
    return parsed


def _parse_unquoted_value(value: str, line_number: int) -> str:
    cleaned = _TRAILING_COMMENT.sub("", value).rstrip()
    if _UNQUOTED_FORBIDDEN.search(cleaned):
        raise EnvParseError(
            f"line {line_number}: unquoted value contains forbidden characters"
        )
    _reject_command_substitution(cleaned, line_number)
    return cleaned


def _parse_assignment(line: str, line_number: int) -> tuple[str, str]:
    assignment = line[len("export ") :].lstrip() if line.startswith("export ") else line
    if "=" not in assignment:
        raise EnvParseError(f"line {line_number}: expected KEY=VALUE assignment")

    key, raw_value = assignment.split("=", 1)
    key = key.strip()
    _validate_key(key, line_number)

    value = raw_value.strip()
    if not value:
        return key, ""
    if value[0] in {"'", '"'}:
        return key, _parse_quoted_value(value, line_number)
    return key, _parse_unquoted_value(value, line_number)


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse an env file into a mapping of variable names to values."""
    if not path.is_file():
        raise EnvParseError(f"env file not found: {path}")

    variables: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.resolve().read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = _parse_assignment(line, line_number)
        variables[key] = value
    return variables
