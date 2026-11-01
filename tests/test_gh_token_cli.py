"""Tests for the GitHub token CLI utility."""

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
    ("val", "expected"),
    [
        ("simple", "'simple'"),
        ("", "''"),
        ("a'b", "'a'\"'\"'b'"),
    ],
)
def test_shell_escaping(val: str, expected: str) -> None:
    assert _shell_escape(val) == expected


def test_parser_options() -> None:
    parser = build_parser()
    opts = parser.parse_args(["conf.env", "--get", "TOKEN", "--export"])
    assert opts.env_file == Path("conf.env")
    assert opts.get == "TOKEN"
    assert opts.export is True


def test_write_requested_variable(capsys: pytest.CaptureFixture[str]) -> None:
    store = {"KEY_A": "val_a"}
    target = Path("sample.env")

    # Success case
    assert write_requested_variable("KEY_A", store, target) == 0
    assert capsys.readouterr().out == "val_a"

    # Not found case
    assert write_requested_variable("UNKNOWN", store, target) == 1
    err_out = capsys.readouterr().err
    assert "error: variable 'UNKNOWN' not found in sample.env" in err_out


def test_write_formatters(capsys: pytest.CaptureFixture[str]) -> None:
    mapping = {"X": "1", "Y": "quote'd"}

    write_exports(mapping)
    assert capsys.readouterr().out == "export X='1'\nexport Y='quote'\"'\"'d'\n"

    write_assignments(mapping)
    assert capsys.readouterr().out == "X=1\nY=quote'd\n"

    # Empty dictionary should produce no output
    write_exports({})
    write_assignments({})
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("file_content", "args", "expected_code", "expected_stdout", "expected_err_substring"),
    [
        ("A=10\nB=20\n", [], 0, "A=10\nB=20\n", None),
        ("A=10\nB=20\n", ["--get", "A"], 0, "10", None),
        ("A=10\nB=20\n", ["--get", "MISSING_VAR"], 1, "", "not found in"),
        ("A=10\n", ["--export"], 0, "export A='10'\n", None),
        ("NOT_VALID", [], 1, "", "error:"),
    ],
)
def test_main_cli_scenarios(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    file_content: str,
    args: list[str],
    expected_code: int,
    expected_stdout: str,
    expected_err_substring: str | None,
) -> None:
    cfg = tmp_path / "env.txt"
    cfg.write_text(file_content, encoding="utf-8")

    cli_args = [str(cfg), *args]
    code = main(cli_args)

    assert code == expected_code
    captured = capsys.readouterr()
    assert captured.out == expected_stdout
    if expected_err_substring:
        assert expected_err_substring in captured.err


def test_main_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "nonexistent.env"
    assert main([str(missing)]) == 1
    assert "error: env file not found:" in capsys.readouterr().err
