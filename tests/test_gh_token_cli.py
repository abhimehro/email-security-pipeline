"""Unit tests for src/utils/gh_token_cli.py.

Verifies argument parsing, output formatters, shell escaping, variable lookup,
and end-to-end CLI execution workflows.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


@pytest.mark.parametrize(
    ("raw_value", "expected_escaped"),
    [
        ("simple", "'simple'"),
        ("", "''"),
        ("hello world", "'hello world'"),
        ("can't", "'can'\"'\"'t'"),
        ("foo'bar'baz", "'foo'\"'\"'bar'\"'\"'baz'"),
        ("$VAR; rm -rf /", "'$VAR; rm -rf /'"),
        ("`whoami`", "'`whoami`'"),
    ],
)
def test_shell_escape(raw_value: str, expected_escaped: str) -> None:
    """Verify single-quote escaping for shell safety."""
    assert _shell_escape(raw_value) == expected_escaped


def test_build_parser_defaults() -> None:
    """Verify parser arguments with positional env_file."""
    parser = build_parser()
    args = parser.parse_args(["path/to/.env"])
    assert args.env_file == Path("path/to/.env")
    assert args.get is None
    assert args.export is False


def test_build_parser_options() -> None:
    """Verify parser flags --get and --export."""
    parser = build_parser()
    args = parser.parse_args(["path/to/.env", "--get", "TOKEN", "--export"])
    assert args.env_file == Path("path/to/.env")
    assert args.get == "TOKEN"
    assert args.export is True


def test_build_parser_missing_required_env_file() -> None:
    """Verify parser exits when required env_file argument is omitted."""
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_write_requested_variable_found(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify write_requested_variable prints variable to stdout and returns 0."""
    variables = {"TOKEN": "secret123", "USER": "alice"}
    exit_code = write_requested_variable("TOKEN", variables, Path(".env"))
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "secret123"
    assert captured.err == ""


def test_write_requested_variable_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify write_requested_variable writes error to stderr and returns 1."""
    variables = {"TOKEN": "secret123"}
    exit_code = write_requested_variable("MISSING", variables, Path(".env"))
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "error: variable 'MISSING' not found in .env" in captured.err


def test_write_exports_empty(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify write_exports outputs nothing when variables dict is empty."""
    write_exports({})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_write_exports_formatted(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify write_exports produces shell export statements with escaped values."""
    variables = {
        "VAR1": "value1",
        "VAR2": "it's special",
    }
    write_exports(variables)
    captured = capsys.readouterr()
    expected = "export VAR1='value1'\nexport VAR2='it'\"'\"'s special'\n"
    assert captured.out == expected
    assert captured.err == ""


def test_write_assignments_empty(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify write_assignments outputs nothing when variables dict is empty."""
    write_assignments({})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_write_assignments_formatted(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify write_assignments produces KEY=value lines."""
    variables = {
        "A": "1",
        "B": "test value",
    }
    write_assignments(variables)
    captured = capsys.readouterr()
    expected = "A=1\nB=test value\n"
    assert captured.out == expected
    assert captured.err == ""


def test_main_default_assignments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify main outputs plain assignments by default."""
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\nBAZ=qux\n", encoding="utf-8")

    exit_code = main([str(env_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == "FOO=bar\nBAZ=qux\n"
    assert captured.err == ""


def test_main_export_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Verify main with --export outputs shell export lines."""
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY='secret key'\n", encoding="utf-8")

    exit_code = main([str(env_file), "--export"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == "export API_KEY='secret key'\n"
    assert captured.err == ""


def test_main_get_existing_variable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify main with --get outputs specific variable value."""
    env_file = tmp_path / ".env"
    env_file.write_text("TOKEN=ghp_abc123\nOTHER=xyz\n", encoding="utf-8")

    exit_code = main([str(env_file), "--get", "TOKEN"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == "ghp_abc123"
    assert captured.err == ""


def test_main_get_nonexistent_variable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify main with --get outputs error on missing variable and exits 1."""
    env_file = tmp_path / ".env"
    env_file.write_text("TOKEN=ghp_abc123\n", encoding="utf-8")

    exit_code = main([str(env_file), "--get", "UNKNOWN"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "error: variable 'UNKNOWN' not found" in captured.err


def test_main_invalid_env_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify main gracefully handles EnvParseError and returns 1."""
    env_file = tmp_path / ".env"
    env_file.write_text("INVALID LINE WITHOUT EQUALS\n", encoding="utf-8")

    exit_code = main([str(env_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "error:" in captured.err


def test_main_missing_env_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Verify main gracefully handles missing env file and returns 1."""
    non_existent = tmp_path / "does_not_exist.env"

    exit_code = main([str(non_existent)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "error: env file not found" in captured.err
