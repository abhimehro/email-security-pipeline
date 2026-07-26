"""CLI for safely reading variables from env files."""

import argparse
import sys
from pathlib import Path

from src.utils.env_file_parser import EnvParseError, parse_env_file


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


def write_requested_variable(name: str, variables: dict[str, str], env_file: Path) -> int:
    value = variables.get(name)
    if value is None:
        print(f"error: variable {name!r} not found in {env_file}", file=sys.stderr)
        return 1
    sys.stdout.write(value)
    return 0


def write_exports(variables: dict[str, str]) -> None:
    if variables:
        sys.stdout.write("".join([f"export {key}={_shell_escape(value)}\n" for key, value in variables.items()]))


def write_assignments(variables: dict[str, str]) -> None:
    if variables:
        sys.stdout.write("".join([f"{key}={value}\n" for key, value in variables.items()]))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        variables = parse_env_file(args.env_file)
    except EnvParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.get:
        return write_requested_variable(args.get, variables, args.env_file)
    if args.export:
        write_exports(variables)
        return 0

    write_assignments(variables)
    return 0
