"""Unit tests for src/utils/gh_token_cli.py.

Tests CLI helpers for parsing and writing environment variables,
including shell escaping, argument parsing, variable lookups,
export generation, and main entrypoint behavior.
"""

from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.utils.env_file_parser import EnvParseError
from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


class TestGhTokenCliHelpers(unittest.TestCase):
    """Tests for helper functions in gh_token_cli."""

    def test_shell_escape_standard_string(self) -> None:
        """Escape simple strings by wrapping them in single quotes."""
        self.assertEqual(_shell_escape("simple_value"), "'simple_value'")

    def test_shell_escape_empty_string(self) -> None:
        """Escape empty string by returning empty single-quoted pair."""
        self.assertEqual(_shell_escape(""), "''")

    def test_shell_escape_embedded_single_quotes(self) -> None:
        """Escape single quotes safely for POSIX shell evaluation."""
        self.assertEqual(_shell_escape("foo'bar"), "'foo'\"'\"'bar'")
        self.assertEqual(_shell_escape("a'b'c"), "'a'\"'\"'b'\"'\"'c'")

    def test_build_parser_arguments(self) -> None:
        """Verify CLI parser configuration for arguments and options."""
        parser = build_parser()

        args = parser.parse_args(["path/to/.env"])
        self.assertEqual(args.env_file, Path("path/to/.env"))
        self.assertIsNone(args.get)
        self.assertFalse(args.export)

        args_get = parser.parse_args(["path/to/.env", "--get", "TOKEN"])
        self.assertEqual(args_get.get, "TOKEN")

        args_export = parser.parse_args(["path/to/.env", "--export"])
        self.assertTrue(args_export.export)

    def test_write_requested_variable_found(self) -> None:
        """Write variable value to stdout and return 0 on hit."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = write_requested_variable(
                "TOKEN", {"TOKEN": "secret123"}, Path(".env")
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "secret123")

    def test_write_requested_variable_missing(self) -> None:
        """Write descriptive error to stderr and return 1 on miss."""
        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = write_requested_variable(
                "MISSING", {"TOKEN": "secret123"}, Path(".env")
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("error: variable 'MISSING' not found in .env", stderr.getvalue())

    def test_write_exports_empty(self) -> None:
        """Write nothing when variables dictionary is empty."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_exports({})

        self.assertEqual(stdout.getvalue(), "")

    def test_write_exports_escaped_output(self) -> None:
        """Write shell export lines with properly escaped values."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_exports({"VAR1": "val1", "VAR2": "val'2"})

        self.assertEqual(
            stdout.getvalue(),
            "export VAR1='val1'\nexport VAR2='val'\"'\"'2'\n",
        )

    def test_write_assignments_empty(self) -> None:
        """Write nothing when variables dictionary is empty."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_assignments({})

        self.assertEqual(stdout.getvalue(), "")

    def test_write_assignments_output(self) -> None:
        """Write plain assignments format separated by newlines."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_assignments({"FOO": "bar", "NUM": "123"})

        self.assertEqual(stdout.getvalue(), "FOO=bar\nNUM=123\n")


class TestGhTokenCliMain(unittest.TestCase):
    """Tests for main() entry point of gh_token_cli."""

    def setUp(self) -> None:
        """Create a temporary directory for test env files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env_path = Path(self.temp_dir.name) / "test.env"
        self.env_path.write_text("API_KEY=xyz789\nSECRET=my'secret\n", encoding="utf-8")

    def tearDown(self) -> None:
        """Clean up temporary directory."""
        self.temp_dir.cleanup()

    def test_main_default_assignments(self) -> None:
        """Default invocation writes plain assignments to stdout."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main([str(self.env_path)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "API_KEY=xyz789\nSECRET=my'secret\n")

    def test_main_export_flag(self) -> None:
        """The --export flag writes shell export commands to stdout."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main([str(self.env_path), "--export"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            stdout.getvalue(),
            "export API_KEY='xyz789'\nexport SECRET='my'\"'\"'secret'\n",
        )

    def test_main_get_existing_variable(self) -> None:
        """The --get flag prints variable value without newlines."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main([str(self.env_path), "--get", "API_KEY"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), "xyz789")

    def test_main_get_missing_variable(self) -> None:
        """The --get flag returns 1 and outputs error when variable is missing."""
        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = main([str(self.env_path), "--get", "NON_EXISTENT"])

        self.assertEqual(exit_code, 1)
        self.assertIn("error: variable 'NON_EXISTENT' not found", stderr.getvalue())

    def test_main_env_parse_error(self) -> None:
        """Catches EnvParseError, prints error message to stderr, and returns 1."""
        stderr = StringIO()
        with (
            patch(
                "src.utils.gh_token_cli.parse_env_file",
                side_effect=EnvParseError("malformed format"),
            ),
            redirect_stderr(stderr),
        ):
            exit_code = main([str(self.env_path)])

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr.getvalue(), "error: malformed format\n")


if __name__ == "__main__":
    unittest.main()
