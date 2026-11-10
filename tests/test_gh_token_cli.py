"""Unit tests for src/utils/gh_token_cli.py.

Verifies argument parsing, output formatters, shell escaping, variable lookup,
and end-to-end CLI execution workflows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, NamedTuple

import pytest

from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


class MainScenario(NamedTuple):
    """Encapsulates test parameters and expected outcomes for main() CLI runs."""

    file_content: str | None
    cli_args: list[str]
    expected_code: int
    expected_out: str
    expected_err_substring: str


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


@pytest.mark.parametrize(
    ("cli_argv", "expected_get", "expected_export"),
    [
        (["path/to/.env"], None, False),
        (["path/to/.env", "--get", "TOKEN", "--export"], "TOKEN", True),
    ],
)
def test_build_parser_options(
    cli_argv: list[str], expected_get: str | None, expected_export: bool
) -> None:
    """Verify parser arguments and flags."""
    args = build_parser().parse_args(cli_argv)
    assert args.env_file == Path("path/to/.env")
    assert args.get == expected_get
    assert args.export is expected_export


def test_build_parser_missing_required_env_file() -> None:
    """Verify parser exits when required env_file argument is omitted."""
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


@pytest.mark.parametrize(
    ("var_name", "store", "expected_code", "expected_out", "expected_err"),
    [
        ("TOKEN", {"TOKEN": "secret123", "USER": "alice"}, 0, "secret123", ""),
        (
            "MISSING",
            {"TOKEN": "secret123"},
            1,
            "",
            "error: variable 'MISSING' not found in .env",
        ),
    ],
)
def test_write_requested_variable(
    capsys: pytest.CaptureFixture[str],
    var_name: str,
    store: dict[str, str],
    expected_code: int,
    expected_out: str,
    expected_err: str,
) -> None:
    """Verify write_requested_variable handling of existing and missing keys."""
    exit_code = write_requested_variable(var_name, store, Path(".env"))
    captured = capsys.readouterr()
    assert exit_code == expected_code
    assert captured.out == expected_out
    if expected_err:
        assert expected_err in captured.err
    else:
        assert captured.err == ""


@pytest.mark.parametrize(
    ("writer_func", "variables", "expected_out"),
    [
        (write_exports, {}, ""),
        (
            write_exports,
            {"VAR1": "val1", "VAR2": "it's special"},
            "export VAR1='val1'\nexport VAR2='it'\"'\"'s special'\n",
        ),
        (write_assignments, {}, ""),
        (
            write_assignments,
            {"A": "1", "B": "test value"},
            "A=1\nB=test value\n",
        ),
    ],
)
def test_format_writers(
    capsys: pytest.CaptureFixture[str],
    writer_func: Callable[[dict[str, str]], None],
    variables: dict[str, str],
    expected_out: str,
) -> None:
    """Verify write_exports and write_assignments for empty and formatted mappings."""
    writer_func(variables)
    assert capsys.readouterr().out == expected_out


@pytest.mark.parametrize(
    "scenario",
    [
        MainScenario(
            file_content="FOO=bar\nBAZ=qux\n",
            cli_args=[],
            expected_code=0,
            expected_out="FOO=bar\nBAZ=qux\n",
            expected_err_substring="",
        ),
        MainScenario(
            file_content="API_KEY='secret key'\n",
            cli_args=["--export"],
            expected_code=0,
            expected_out="export API_KEY='secret key'\n",
            expected_err_substring="",
        ),
        MainScenario(
            file_content="TOKEN=ghp_abc123\nOTHER=xyz\n",
            cli_args=["--get", "TOKEN"],
            expected_code=0,
            expected_out="ghp_abc123",
            expected_err_substring="",
        ),
        MainScenario(
            file_content="TOKEN=ghp_abc123\n",
            cli_args=["--get", "UNKNOWN"],
            expected_code=1,
            expected_out="",
            expected_err_substring="error: variable 'UNKNOWN' not found",
        ),
        MainScenario(
            file_content="INVALID LINE WITHOUT EQUALS\n",
            cli_args=[],
            expected_code=1,
            expected_out="",
            expected_err_substring="error:",
        ),
        MainScenario(
            file_content=None,
            cli_args=[],
            expected_code=1,
            expected_out="",
            expected_err_substring="error: env file not found",
        ),
    ],
)
def test_main_scenarios(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], scenario: MainScenario
) -> None:
    """Verify end-to-end CLI execution workflows."""
    env_file = tmp_path / "test.env"
    if scenario.file_content is not None:
        env_file.write_text(scenario.file_content, encoding="utf-8")

    exit_code = main([str(env_file), *scenario.cli_args])
    captured = capsys.readouterr()

    assert exit_code == scenario.expected_code
    assert captured.out == scenario.expected_out
    if scenario.expected_err_substring:
        assert scenario.expected_err_substring in captured.err
    else:
        assert captured.err == ""
