"""Tests for gh_token_cli module."""

from __future__ import annotations

from pathlib import Path

from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


def test_shell_escape_standard_and_single_quotes() -> None:
    assert _shell_escape("normal_value") == "'normal_value'"
    assert _shell_escape("") == "''"
    assert _shell_escape("it's a test") == "'it'\"'\"'s a test'"
    assert _shell_escape("'''") == "''\"'\"''\"'\"''\"'\"''"


def test_build_parser_arguments() -> None:
    parser = build_parser()
    args = parser.parse_args(["path/to/.env", "--get", "GH_TOKEN", "--export"])
    assert args.env_file == Path("path/to/.env")
    assert args.get == "GH_TOKEN"
    assert args.export is True


def test_write_requested_variable_found(capsys) -> None:
    env_file = Path(".env")
    variables = {"GH_TOKEN": "token_val_123", "OTHER": "xyz"}
    ret = write_requested_variable("GH_TOKEN", variables, env_file)
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out == "token_val_123"
    assert captured.err == ""


def test_write_requested_variable_missing(capsys) -> None:
    env_file = Path(".env")
    variables = {"GH_TOKEN": "token_val_123"}
    ret = write_requested_variable("NONEXISTENT", variables, env_file)
    assert ret == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error: variable 'NONEXISTENT' not found in .env\n" == captured.err


def test_write_exports(capsys) -> None:
    variables = {"FOO": "bar", "BAZ": "qux's"}
    write_exports(variables)
    captured = capsys.readouterr()
    assert captured.out == "export FOO='bar'\nexport BAZ='qux'\"'\"'s'\n"
    assert captured.err == ""

    # Empty dictionary test
    write_exports({})
    captured_empty = capsys.readouterr()
    assert captured_empty.out == ""
    assert captured_empty.err == ""


def test_write_assignments(capsys) -> None:
    variables = {"FOO": "bar", "BAZ": "qux"}
    write_assignments(variables)
    captured = capsys.readouterr()
    assert captured.out == "FOO=bar\nBAZ=qux\n"
    assert captured.err == ""

    # Empty dictionary test
    write_assignments({})
    captured_empty = capsys.readouterr()
    assert captured_empty.out == ""
    assert captured_empty.err == ""


def test_main_default_assignments(tmp_path: Path, capsys) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("VAR1=value1\nVAR2=value2\n", encoding="utf-8")

    ret = main([str(env_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out == "VAR1=value1\nVAR2=value2\n"
    assert captured.err == ""


def test_main_get_flag(tmp_path: Path, capsys) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("VAR1=value1\nVAR2=value2\n", encoding="utf-8")

    ret = main([str(env_path), "--get", "VAR2"])
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out == "value2"
    assert captured.err == ""


def test_main_get_flag_missing(tmp_path: Path, capsys) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("VAR1=value1\n", encoding="utf-8")

    ret = main([str(env_path), "--get", "MISSING"])
    assert ret == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"error: variable 'MISSING' not found in {env_path}\n" == captured.err


def test_main_export_flag(tmp_path: Path, capsys) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("TOKEN=secret_token\n", encoding="utf-8")

    ret = main([str(env_path), "--export"])
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out == "export TOKEN='secret_token'\n"
    assert captured.err == ""


def test_main_parse_error(tmp_path: Path, capsys) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("INVALID LINE WITHOUT EQUALS\n", encoding="utf-8")

    ret = main([str(env_path)])
    assert ret == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


def test_main_nonexistent_file(tmp_path: Path, capsys) -> None:
    nonexistent = tmp_path / "does_not_exist.env"

    ret = main([str(nonexistent)])
    assert ret == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"error: env file not found: {nonexistent}\n" == captured.err
