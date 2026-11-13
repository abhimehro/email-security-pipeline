"""Unit tests for gh_token_cli module."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from src.utils.gh_token_cli import (
    _shell_escape,
    build_parser,
    main,
    write_assignments,
    write_exports,
    write_requested_variable,
)


class TestGhTokenCliUnit(unittest.TestCase):
    """Test suite for functions and CLI behavior in gh_token_cli."""

    def setUp(self) -> None:
        """Create a temporary directory for test env files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        """Clean up the temporary directory."""
        self.temp_dir.cleanup()

    def _create_env_file(self, content: str) -> Path:
        """Create a temporary env file with specific content."""
        env_path = self.test_dir / "test.env"
        env_path.write_text(content, encoding="utf-8")
        return env_path

    # --- _shell_escape tests ---

    def test_shell_escape_simple_strings(self) -> None:
        """Test escaping on standard values without quotes."""
        self.assertEqual(_shell_escape(""), "''")
        self.assertEqual(_shell_escape("abc123"), "'abc123'")
        self.assertEqual(_shell_escape("hello world"), "'hello world'")
        self.assertEqual(_shell_escape("var=val"), "'var=val'")

    def test_shell_escape_single_quotes(self) -> None:
        """Test escaping when input contains single quotes."""
        self.assertEqual(_shell_escape("don't"), "'don'\"'\"'t'")
        self.assertEqual(_shell_escape("'start"), "''\"'\"'start'")
        self.assertEqual(_shell_escape("end'"), "'end'\"'\"''")
        self.assertEqual(_shell_escape("'''"), "''\"'\"''\"'\"''\"'\"''")

    # --- build_parser tests ---

    def test_build_parser_options(self) -> None:
        """Test CLI argument parsing and flags."""
        parser = build_parser()
        args = parser.parse_args(["my.env"])
        self.assertEqual(args.env_file, Path("my.env"))
        self.assertIsNone(args.get)
        self.assertFalse(args.export)

        args = parser.parse_args(["my.env", "--get", "FOO"])
        self.assertEqual(args.get, "FOO")
        self.assertFalse(args.export)

        args = parser.parse_args(["my.env", "--export"])
        self.assertIsNone(args.get)
        self.assertTrue(args.export)

    def test_build_parser_requires_env_file(self) -> None:
        """Test that missing positional env_file argument raises SystemExit."""
        parser = build_parser()
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as ctx:
            parser.parse_args([])
        self.assertNotEqual(ctx.exception.code, 0)

    # --- write_requested_variable tests ---

    def test_write_requested_variable_found(self) -> None:
        """Test writing existing variable to stdout with exit code 0."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = write_requested_variable(
                "TOKEN", {"TOKEN": "secret123"}, Path(".env")
            )
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "secret123")

    def test_write_requested_variable_missing(self) -> None:
        """Test missing variable returns 1 and prints error to stderr."""
        stderr = StringIO()
        with redirect_stderr(stderr):
            code = write_requested_variable(
                "NONEXISTENT", {"TOKEN": "secret123"}, Path(".env")
            )
        self.assertEqual(code, 1)
        self.assertIn(
            "error: variable 'NONEXISTENT' not found in .env",
            stderr.getvalue(),
        )

    def test_write_requested_variable_empty_value(self) -> None:
        """Test retrieving variable that is set to empty string."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = write_requested_variable("EMPTY", {"EMPTY": ""}, Path(".env"))
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), "")

    # --- write_exports tests ---

    def test_write_exports_empty_dict(self) -> None:
        """Test writing exports when dictionary is empty writes nothing."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_exports({})
        self.assertEqual(stdout.getvalue(), "")

    def test_write_exports_formats_with_shell_escape(self) -> None:
        """Test writing exports properly escapes values for shell."""
        stdout = StringIO()
        variables = {"KEY1": "val1", "KEY2": "val'with'quotes", "EMPTY": ""}
        with redirect_stdout(stdout):
            write_exports(variables)
        expected = (
            "export KEY1='val1'\n"
            "export KEY2='val'\"'\"'with'\"'\"'quotes'\n"
            "export EMPTY=''\n"
        )
        self.assertEqual(stdout.getvalue(), expected)

    # --- write_assignments tests ---

    def test_write_assignments_empty_dict(self) -> None:
        """Test writing assignments when dictionary is empty writes nothing."""
        stdout = StringIO()
        with redirect_stdout(stdout):
            write_assignments({})
        self.assertEqual(stdout.getvalue(), "")

    def test_write_assignments_formats_raw(self) -> None:
        """Test writing plain KEY=value assignments."""
        stdout = StringIO()
        variables = {"A": "1", "B": "hello", "C": ""}
        with redirect_stdout(stdout):
            write_assignments(variables)
        expected = "A=1\nB=hello\nC=\n"
        self.assertEqual(stdout.getvalue(), expected)

    # --- main tests ---

    def test_main_get_success(self) -> None:
        """Test main entry point with --get retrieving a token."""
        env_file = self._create_env_file("GH_TOKEN=token_abc123\n")
        stdout = StringIO()
        with redirect_stdout(stdout):
            ret = main([str(env_file), "--get", "GH_TOKEN"])
        self.assertEqual(ret, 0)
        self.assertEqual(stdout.getvalue(), "token_abc123")

    def test_main_get_not_found(self) -> None:
        """Test main entry point with --get for a missing token."""
        env_file = self._create_env_file("GH_TOKEN=token_abc123\n")
        stderr = StringIO()
        with redirect_stderr(stderr):
            ret = main([str(env_file), "--get", "MISSING_VAR"])
        self.assertEqual(ret, 1)
        self.assertIn("error: variable 'MISSING_VAR' not found", stderr.getvalue())

    def test_main_export_flag(self) -> None:
        """Test main entry point with --export."""
        env_file = self._create_env_file("FOO=bar\nBAZ='qux'\n")
        stdout = StringIO()
        with redirect_stdout(stdout):
            ret = main([str(env_file), "--export"])
        self.assertEqual(ret, 0)
        self.assertEqual(stdout.getvalue(), "export FOO='bar'\nexport BAZ='qux'\n")

    def test_main_default_assignments(self) -> None:
        """Test main entry point default output without --get or --export."""
        env_file = self._create_env_file("FOO=bar\nBAZ=123\n")
        stdout = StringIO()
        with redirect_stdout(stdout):
            ret = main([str(env_file)])
        self.assertEqual(ret, 0)
        self.assertEqual(stdout.getvalue(), "FOO=bar\nBAZ=123\n")

    def test_main_empty_env_file(self) -> None:
        """Test main entry point on empty env file."""
        env_file = self._create_env_file("")
        stdout = StringIO()
        with redirect_stdout(stdout):
            ret_default = main([str(env_file)])
            ret_export = main([str(env_file), "--export"])
        self.assertEqual(ret_default, 0)
        self.assertEqual(ret_export, 0)
        self.assertEqual(stdout.getvalue(), "")

    def test_main_parse_error(self) -> None:
        """Test main entry point when env file cannot be parsed."""
        env_file = self._create_env_file("INVALID LINE NO EQUALS\n")
        stderr = StringIO()
        with redirect_stderr(stderr):
            ret = main([str(env_file)])
        self.assertEqual(ret, 1)
        self.assertIn("error:", stderr.getvalue())

    def test_main_nonexistent_file(self) -> None:
        """Test main entry point when env file does not exist."""
        nonexistent = self.test_dir / "does_not_exist.env"
        stderr = StringIO()
        with redirect_stderr(stderr):
            ret = main([str(nonexistent)])
        self.assertEqual(ret, 1)
        self.assertIn("error: env file not found", stderr.getvalue())

    def test_main_missing_arguments_raises_system_exit(self) -> None:
        """Test main entry point exits with error code when arguments are missing."""
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as ctx:
            main([])
        self.assertNotEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
