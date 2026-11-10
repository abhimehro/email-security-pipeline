"""Unit tests for src/utils/gh_token_cli.py.

Verifies CLI argument parsing, shell escaping, variable reading,
and output formatting for environment file variables.
"""

from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Iterator

import pytest

from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main as cli_main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


@contextmanager
def temporary_env_file(content: str) -> Iterator[Path]:
    """Yield a temporary environment file path containing given content."""
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(content)
        path = Path(handle.name)
    try:
        yield path
    finally:
        path.unlink()


class TestGhTokenCliFunctions(unittest.TestCase):
    """Test individual helper functions within gh_token_cli."""

    def test_shell_escape_variations(self) -> None:
        """Test _shell_escape against various inputs."""
        test_cases = [
            ("plain", "'plain'"),
            ("", "''"),
            ("it's", "'it'\"'\"'s'"),
            ("multiple'single'quotes", "'multiple'\"'\"'single'\"'\"'quotes'"),
            ("foo'bar $VAR `id`", "'foo'\"'\"'bar $VAR `id`'"),
        ]
        for input_val, expected in test_cases:
            with self.subTest(input_val=input_val):
                self.assertEqual(_shell_escape(input_val), expected)

    def test_build_parser_options(self) -> None:
        """Test build_parser parses positional and optional arguments."""
        parser = build_parser()

        # Parse basic positional env_file
        args = parser.parse_args(["path/to/.env"])
        self.assertEqual(args.env_file, Path("path/to/.env"))
        self.assertIsNone(args.get)
        self.assertFalse(args.export)

        # Parse --get argument
        args_get = parser.parse_args(["path/to/.env", "--get", "GH_TOKEN"])
        self.assertEqual(args_get.get, "GH_TOKEN")

        # Parse --export flag
        args_export = parser.parse_args(["path/to/.env", "--export"])
        self.assertTrue(args_export.export)

    def test_build_parser_requires_env_file(self) -> None:
        """Test build_parser requires the env_file positional argument."""
        parser = build_parser()
        with redirect_stderr(StringIO()), pytest.raises(SystemExit):
            parser.parse_args([])

    def test_write_requested_variable_found(self) -> None:
        """Test write_requested_variable outputs variable value and returns 0."""
        stdout = StringIO()
        variables = {"TOKEN": "secret_abc_123"}
        with redirect_stdout(stdout):
            exit_code = write_requested_variable("TOKEN", variables, Path(".env"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "secret_abc_123")

    def test_write_requested_variable_missing(self) -> None:
        """Test write_requested_variable outputs error to stderr and returns 1."""
        stdout = StringIO()
        stderr = StringIO()
        variables = {"TOKEN": "secret_abc_123"}
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = write_requested_variable(
                "OTHER_VAR", variables, Path("custom.env")
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error: variable 'OTHER_VAR' not found in custom.env", stderr.getvalue())

    def test_write_exports_with_variables(self) -> None:
        """Test write_exports formats variables with export and quotes."""
        stdout = StringIO()
        variables = {"FOO": "bar", "SAY": "it's working"}
        with redirect_stdout(stdout):
            write_exports(variables)

        expected = "export FOO='bar'\nexport SAY='it'\"'\"'s working'\n"
        self.assertEqual(stdout.getvalue(), expected)

    def test_write_exports_empty(self) -> None:
        """Test write_exports does nothing when given an empty dictionary."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_exports({})

        self.assertEqual(stdout.getvalue(), "")

    def test_write_assignments_with_variables(self) -> None:
        """Test write_assignments outputs KEY=VALUE without quotes."""
        stdout = StringIO()
        variables = {"VAR_A": "1", "VAR_B": "two"}
        with redirect_stdout(stdout):
            write_assignments(variables)

        expected = "VAR_A=1\nVAR_B=two\n"
        self.assertEqual(stdout.getvalue(), expected)

    def test_write_assignments_empty(self) -> None:
        """Test write_assignments does nothing when given an empty dictionary."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_assignments({})

        self.assertEqual(stdout.getvalue(), "")


class TestGhTokenCliMain(unittest.TestCase):
    """Test CLI main entry point with different flags and inputs."""

    def test_main_get_existing_variable(self) -> None:
        """Test main returns 0 and prints value when --get matches a variable."""
        with temporary_env_file("GH_TOKEN=token123\n") as path:
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = cli_main([str(path), "--get", "GH_TOKEN"])
            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), "token123")

    def test_main_get_missing_variable(self) -> None:
        """Test main returns 1 and prints error to stderr when --get does not match."""
        with temporary_env_file("GH_TOKEN=token123\n") as path:
            stderr = StringIO()
            with redirect_stderr(stderr):
                code = cli_main([str(path), "--get", "UNKNOWN"])
            self.assertEqual(code, 1)
            self.assertIn("error: variable 'UNKNOWN' not found in", stderr.getvalue())

    def test_main_export_mode(self) -> None:
        """Test main in --export mode formats all variables with shell exports."""
        with temporary_env_file("VAR1=alpha\nVAR2=beta's\n") as path:
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = cli_main([str(path), "--export"])
            self.assertEqual(code, 0)
            self.assertIn("export VAR1='alpha'\n", stdout.getvalue())
            self.assertIn("export VAR2='beta'\"'\"'s'\n", stdout.getvalue())

    def test_main_default_assignment_mode(self) -> None:
        """Test main in default mode formats all variables as simple assignments."""
        with temporary_env_file("PORT=8080\nHOST=localhost\n") as path:
            stdout = StringIO()
            with redirect_stdout(stdout):
                code = cli_main([str(path)])
            self.assertEqual(code, 0)
            self.assertIn("PORT=8080\n", stdout.getvalue())
            self.assertIn("HOST=localhost\n", stdout.getvalue())

    def test_main_handles_parse_error(self) -> None:
        """Test main returns 1 and outputs error message when env file is invalid."""
        with temporary_env_file("INVALID LINE NO EQUALS\n") as path:
            stderr = StringIO()
            with redirect_stderr(stderr):
                code = cli_main([str(path)])
            self.assertEqual(code, 1)
            self.assertIn("error:", stderr.getvalue())

    def test_main_invalid_args_raises_system_exit(self) -> None:
        """Test main raises SystemExit on missing mandatory arguments."""
        with redirect_stderr(StringIO()), pytest.raises(SystemExit):
            cli_main([])


if __name__ == "__main__":
    unittest.main()
