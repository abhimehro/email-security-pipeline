#!/usr/bin/env python3
"""CLI for safely reading variables from env files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.utils.env_file_parser import EnvParseError, parse_env_file  # noqa: E402


def _shell_escape(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely read variables from an env file without shell execution."
    )
    parser.add_argument("env_file", type=Path)
    parser.add_argument("--get", metavar="VAR")
    parser.add_argument("--export", action="store_true")
    return parser


def emit_variables(args: argparse.Namespace, variables: dict[str, str]) -> int:
    if args.get:
        value = variables.get(args.get)
        if value is None:
            print(f"error: variable {args.get!r} not found in {args.env_file}", file=sys.stderr)
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        variables = parse_env_file(args.env_file)
    except EnvParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return emit_variables(args, variables)


if __name__ == "__main__":
    raise SystemExit(main())
