#!/usr/bin/env python3
"""Safely parse environment files without executing shell commands.

SECURITY: Never use ``source`` or ``.`` to load env files — they execute arbitrary
shell. This module only extracts ``KEY=VALUE`` assignments with strict validation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# ASSUMES: env files follow shell-style identifier rules for variable names.
_VALID_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TRAILING_COMMENT = re.compile(r"\s+#.*$")

# SECURITY: reject shell metacharacters in unquoted values.
_UNQUOTED_FORBIDDEN = re.compile(r"[\s;|&`$<>()\\]")

# SECURITY: reject command substitution even inside quoted values.
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


def _strip_unquoted_comment(raw_value: str) -> str:
    if raw_value.startswith(("'", '"')):
        return raw_value
    return _TRAILING_COMMENT.sub("", raw_value).rstrip()


def _parse_quoted_value(value: str, line_number: int) -> str:
    quote = value[0]
    if len(value) < 2 or value[-1] != quote:
        raise EnvParseError(f"line {line_number}: unterminated quoted value")
    parsed = value[1:-1]
    _reject_command_substitution(parsed, line_number)
    return parsed


def _parse_unquoted_value(value: str, line_number: int) -> str:
    if _UNQUOTED_FORBIDDEN.search(value):
        raise EnvParseError(
            f"line {line_number}: unquoted value contains forbidden characters"
        )
    _reject_command_substitution(value, line_number)
    return value


def _parse_value(raw_value: str, line_number: int) -> str:
    value = _strip_unquoted_comment(raw_value.strip())
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        return _parse_quoted_value(value, line_number)
    return _parse_unquoted_value(value, line_number)


def _parse_assignment(line: str, line_number: int) -> tuple[str, str]:
    assignment = line[len("export ") :].lstrip() if line.startswith("export ") else line
    if "=" not in assignment:
        raise EnvParseError(f"line {line_number}: expected KEY=VALUE assignment")

    key, raw_value = assignment.split("=", 1)
    key = key.strip()
    _validate_key(key, line_number)
    return key, _parse_value(raw_value, line_number)


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


def _shell_escape(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely read variables from an env file without shell execution."
    )
    parser.add_argument(
        "env_file",
        type=Path,
        help="Path to the env file (for example GH_TOKEN.env)",
    )
    parser.add_argument(
        "--get",
        metavar="VAR",
        help="Print a single variable value to stdout",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Print shell export statements for all variables",
    )
    return parser


def _write_single_variable(name: str, variables: dict[str, str], env_file: Path) -> int:
    value = variables.get(name)
    if value is None:
        print(f"error: variable {name!r} not found in {env_file}", file=sys.stderr)
        return 1
    sys.stdout.write(value)
    return 0


def _write_exports(variables: dict[str, str]) -> None:
    for key, value in variables.items():
        sys.stdout.write(f"export {key}={_shell_escape(value)}\n")


def _write_assignments(variables: dict[str, str]) -> None:
    for key, value in variables.items():
        sys.stdout.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        variables = parse_env_file(args.env_file)
    except EnvParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.get:
        return _write_single_variable(args.get, variables, args.env_file)
    if args.export:
        _write_exports(variables)
        return 0

    _write_assignments(variables)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
