"""Unit tests for src/utils/gh_token_cli.py.

Verifies command-line interface behavior, argument parsing, variable querying,
shell export formatting, shell assignment formatting, and error handling.
"""

from __future__ import annotations

import tempfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Iterator
import pytest

from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


@pytest.fixture
def temp_env_file() -> Iterator[Path]:
    """Provide a temporary env file for testing."""
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        path = Path(handle.name)
    try:
        yield path
    finally:
        if path.exists():
            path.unlink()


@pytest.mark.parametrize(
    ("raw_value", "expected_escaped"),
    [
        ("", "''"),
        ("simple", "'simple'"),
        ("token_12345", "'token_12345'"),
        ("it's", "'it'\"'\"'s'"),
        ("it's a 'quote'", "'it'\"'\"'s a '\"'\"'quote'\"'\"''"),
        ("hello world", "'hello world'"),
        ('double"quote', "'double\"quote'"),
        ("special$char;`test`", "'special$char;`test`'"),
    ],
)
def test_shell_escape(raw_value: str, expected_escaped: str) -> None:
    """Test _shell_escape handles empty strings, quotes, and special characters."""
    assert _shell_escape(raw_value) == expected_escaped


def test_build_parser_options() -> None:
    """Test build_parser generates parser with expected arguments."""
    parser = build_parser()

    # Positional env_file
    args = parser.parse_args(["path/to/.env"])
    assert args.env_file == Path("path/to/.env")
    assert args.get is None
    assert args.export is False

    # --get option
    args_get = parser.parse_args(["path/to/.env", "--get", "GH_TOKEN"])
    assert args_get.env_file == Path("path/to/.env")
    assert args_get.get == "GH_TOKEN"
    assert args_get.export is False

    # --export option
    args_export = parser.parse_args(["path/to/.env", "--export"])
    assert args_export.env_file == Path("path/to/.env")
    assert args_export.get is None
    assert args_export.export is True


def test_write_requested_variable_found() -> None:
    """Test write_requested_variable prints variable value and returns 0."""
    variables = {"TOKEN": "secret_abc_123", "PORT": "8080"}
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        exit_code = write_requested_variable("TOKEN", variables, Path(".env"))

    assert exit_code == 0
    assert buf_stdout.getvalue() == "secret_abc_123"


def test_write_requested_variable_missing() -> None:
    """Test write_requested_variable prints error to stderr and returns 1."""
    variables = {"TOKEN": "secret_abc_123"}
    buf_stderr = StringIO()

    with redirect_stderr(buf_stderr):
        exit_code = write_requested_variable("NONEXISTENT", variables, Path(".env"))

    assert exit_code == 1
    assert "error: variable 'NONEXISTENT' not found in .env" in buf_stderr.getvalue()


def test_write_exports_with_variables() -> None:
    """Test write_exports writes escaped export statements."""
    variables = {"KEY1": "val1", "KEY2": "val's"}
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        write_exports(variables)

    output = buf_stdout.getvalue()
    assert "export KEY1='val1'\n" in output
    assert "export KEY2='val'\"'\"'s'\n" in output


def test_write_exports_empty_variables() -> None:
    """Test write_exports with empty dict writes nothing."""
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        write_exports({})

    assert buf_stdout.getvalue() == ""


def test_write_assignments_with_variables() -> None:
    """Test write_assignments writes key=value lines."""
    variables = {"KEY1": "val1", "KEY2": "val2"}
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        write_assignments(variables)

    output = buf_stdout.getvalue()
    assert output == "KEY1=val1\nKEY2=val2\n"


def test_write_assignments_empty_variables() -> None:
    """Test write_assignments with empty dict writes nothing."""
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        write_assignments({})

    assert buf_stdout.getvalue() == ""


def test_main_default_assignments(temp_env_file: Path) -> None:
    """Test main without flags prints assignments."""
    temp_env_file.write_text("FOO=bar\nBAZ=qux\n", encoding="utf-8")
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        exit_code = main([str(temp_env_file)])

    assert exit_code == 0
    assert buf_stdout.getvalue() == "FOO=bar\nBAZ=qux\n"


def test_main_export_flag(temp_env_file: Path) -> None:
    """Test main with --export writes export statements."""
    temp_env_file.write_text("TOKEN=ghp_xyz123\nNAME=test\n", encoding="utf-8")
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        exit_code = main([str(temp_env_file), "--export"])

    assert exit_code == 0
    assert "export TOKEN='ghp_xyz123'\n" in buf_stdout.getvalue()
    assert "export NAME='test'\n" in buf_stdout.getvalue()


def test_main_get_existing_variable(temp_env_file: Path) -> None:
    """Test main with --get returns requested variable value."""
    temp_env_file.write_text("MY_VAR=secret_value\nOTHER=ignore\n", encoding="utf-8")
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        exit_code = main([str(temp_env_file), "--get", "MY_VAR"])

    assert exit_code == 0
    assert buf_stdout.getvalue() == "secret_value"


def test_main_get_missing_variable(temp_env_file: Path) -> None:
    """Test main with --get for missing variable returns 1 and prints error."""
    temp_env_file.write_text("MY_VAR=secret_value\n", encoding="utf-8")
    buf_stderr = StringIO()

    with redirect_stderr(buf_stderr):
        exit_code = main([str(temp_env_file), "--get", "NON_EXISTENT"])

    assert exit_code == 1
    assert "error: variable 'NON_EXISTENT' not found in" in buf_stderr.getvalue()


def test_main_env_parse_error(temp_env_file: Path) -> None:
    """Test main with malformed env file prints error to stderr and returns 1."""
    temp_env_file.write_text("INVALID LINE WITHOUT EQUALS\n", encoding="utf-8")
    buf_stderr = StringIO()

    with redirect_stderr(buf_stderr):
        exit_code = main([str(temp_env_file)])

    assert exit_code == 1
    assert "error:" in buf_stderr.getvalue()


def test_main_missing_file() -> None:
    """Test main with non-existent file returns 1 and prints error."""
    non_existent = Path("non_existent_file.env")
    buf_stderr = StringIO()

    with redirect_stderr(buf_stderr):
        exit_code = main([str(non_existent)])

    assert exit_code == 1
    assert "error: env file not found" in buf_stderr.getvalue()


def test_main_empty_env_file(temp_env_file: Path) -> None:
    """Test main with empty env file runs cleanly."""
    temp_env_file.write_text("", encoding="utf-8")
    buf_stdout = StringIO()

    with redirect_stdout(buf_stdout):
        exit_code = main([str(temp_env_file)])

    assert exit_code == 0
    assert buf_stdout.getvalue() == ""
