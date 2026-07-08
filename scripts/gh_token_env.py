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

# SECURITY: reject shell metacharacters in unquoted values.
_UNQUOTED_FORBIDDEN = re.compile(r"[\s;|&`$<>()\\]")

# SECURITY: reject command substitution even inside quoted values.
_COMMAND_SUBSTITUTION = re.compile(r"\$\(|`")


class EnvParseError(ValueError):
    """Raised when an env file contains unsafe or malformed content."""


def _strip_inline_comment(value: str) -> str:
    in_single = False
    in_double = False
    escaped = False

    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_double:
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if char == "#" and not in_single and not in_double:
            return value[:index].rstrip()
    return value


def _parse_value(raw_value: str, line_number: int) -> str:
    value = raw_value.strip()
    if not value:
        return ""

    if value[0] in {"'", '"'}:
        quote = value[0]
        if len(value) < 2 or value[-1] != quote:
            raise EnvParseError(
                f"line {line_number}: unterminated quoted value"
            )
        parsed = value[1:-1]
        if _COMMAND_SUBSTITUTION.search(parsed):
            raise EnvParseError(
                f"line {line_number}: command substitution is not allowed"
            )
        return parsed

    if _UNQUOTED_FORBIDDEN.search(value):
        raise EnvParseError(
            f"line {line_number}: unquoted value contains forbidden characters"
        )
    if _COMMAND_SUBSTITUTION.search(value):
        raise EnvParseError(
            f"line {line_number}: command substitution is not allowed"
        )
    return value


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse an env file into a mapping of variable names to values."""
    if not path.is_file():
        raise EnvParseError(f"env file not found: {path}")

    resolved = path.resolve()
    variables: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        resolved.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()

        if "=" not in line:
            raise EnvParseError(
                f"line {line_number}: expected KEY=VALUE assignment"
            )

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not _VALID_KEY.fullmatch(key):
            raise EnvParseError(f"line {line_number}: invalid variable name {key!r}")

        value = _parse_value(_strip_inline_comment(raw_value), line_number)
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        variables = parse_env_file(args.env_file)
    except EnvParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.get:
        value = variables.get(args.get)
        if value is None:
            print(
                f"error: variable {args.get!r} not found in {args.env_file}",
                file=sys.stderr,
            )
            return 1
        sys.stdout.write(value)
        return 0

    if args.export:
        for key, value in variables.items():
            sys.stdout.write(f"export {key}={_shell_escape(value)}\n")
        return 0

    for key, value in variables.items():
        sys.stdout.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
