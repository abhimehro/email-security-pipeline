"""Unit tests for src/utils/env_file_parser.py.

Tests safe parsing of environment files without shell execution, verifying key validation,
quote handling, forbidden character rejection, and command substitution prevention.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.utils.env_file_parser import (
    EnvParseError,
    _parse_assignment,
    _parse_quoted_value,
    _parse_unquoted_value,
    _reject_command_substitution,
    _validate_key,
    parse_env_file,
)


class TestEnvFileParser(unittest.TestCase):
    """Test suite for env_file_parser module functions and edge cases."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_env_file(self, content: str) -> Path:
        file_path = self.test_dir / "test.env"
        file_path.write_text(content, encoding="utf-8")
        return file_path

    # --- Key validation tests ---

    def test_validate_key_valid_names(self) -> None:
        valid_keys = [
            "KEY",
            "key",
            "_KEY",
            "KEY_123",
            "API_KEY_V2",
            "_",
            "a",
            "A",
            "_123",
        ]
        for key in valid_keys:
            with self.subTest(key=key):
                # Should not raise
                _validate_key(key, 1)

    def test_validate_key_invalid_names(self) -> None:
        invalid_keys = [
            "",
            "123KEY",
            "KEY-NAME",
            "KEY.NAME",
            "KEY NAME",
            "KEY$NAME",
            "KEY=VALUE",
            "KEY@NAME",
        ]
        for key in invalid_keys:
            with self.subTest(key=key):
                with self.assertRaises(EnvParseError) as ctx:
                    _validate_key(key, 42)
                self.assertIn("line 42", str(ctx.exception))
                self.assertIn("invalid variable name", str(ctx.exception))

    # --- Command substitution rejection tests ---

    def test_reject_command_substitution_safe_values(self) -> None:
        safe_values = [
            "normal_value",
            "value_with_$variable_without_parens",
            "$VAR",
            "value-123",
            "",
        ]
        for val in safe_values:
            with self.subTest(val=val):
                # Should not raise
                _reject_command_substitution(val, 1)

    def test_reject_command_substitution_detected(self) -> None:
        dangerous_values = [
            "$(whoami)",
            "prefix_$(rm -rf /)_suffix",
            "`whoami`",
            "value_`id`_test",
        ]
        for val in dangerous_values:
            with self.subTest(val=val):
                with self.assertRaises(EnvParseError) as ctx:
                    _reject_command_substitution(val, 10)
                self.assertIn("line 10", str(ctx.exception))
                self.assertIn("command substitution is not allowed", str(ctx.exception))

    # --- Quoted value parsing tests ---

    def test_parse_quoted_value_single_and_double_quotes(self) -> None:
        self.assertEqual(_parse_quoted_value("''", 1), "")
        self.assertEqual(_parse_quoted_value('""', 1), "")
        self.assertEqual(_parse_quoted_value("'hello world'", 1), "hello world")
        self.assertEqual(_parse_quoted_value('"hello world"', 1), "hello world")

    def test_parse_quoted_value_allows_special_characters(self) -> None:
        # Characters forbidden in unquoted values are allowed within quotes
        quoted = '"hello; world & foo | bar < baz > test \\ path"'
        self.assertEqual(
            _parse_quoted_value(quoted, 1),
            "hello; world & foo | bar < baz > test \\ path",
        )

    def test_parse_quoted_value_unterminated_or_mismatched(self) -> None:
        unterminated_cases = [
            "'",
            '"',
            "'hello",
            '"hello',
            "'hello\"",
            '"hello\'',
        ]
        for val in unterminated_cases:
            with self.subTest(val=val):
                with self.assertRaises(EnvParseError) as ctx:
                    _parse_quoted_value(val, 5)
                self.assertIn("line 5", str(ctx.exception))
                self.assertIn("unterminated quoted value", str(ctx.exception))

    def test_parse_quoted_value_rejects_command_substitution(self) -> None:
        with self.assertRaises(EnvParseError) as ctx:
            _parse_quoted_value('"$(cat /etc/passwd)"', 7)
        self.assertIn("line 7", str(ctx.exception))
        self.assertIn("command substitution is not allowed", str(ctx.exception))

        with self.assertRaises(EnvParseError) as ctx:
            _parse_quoted_value("'`uname -a`'", 8)
        self.assertIn("line 8", str(ctx.exception))
        self.assertIn("command substitution is not allowed", str(ctx.exception))

    # --- Unquoted value parsing tests ---

    def test_parse_unquoted_value_valid(self) -> None:
        self.assertEqual(_parse_unquoted_value("simple_value", 1), "simple_value")
        self.assertEqual(_parse_unquoted_value("12345", 1), "12345")
        self.assertEqual(_parse_unquoted_value("a-b_c.d", 1), "a-b_c.d")

    def test_parse_unquoted_value_strips_trailing_comments(self) -> None:
        self.assertEqual(
            _parse_unquoted_value("simple_value # trailing comment", 1),
            "simple_value",
        )
        self.assertEqual(
            _parse_unquoted_value("val    # multiple spaces before comment", 1),
            "val",
        )

    def test_parse_unquoted_value_forbidden_characters(self) -> None:
        forbidden_samples = [
            "has space",
            "semi;colon",
            "pipe|command",
            "amp&ersand",
            "back`tick",
            "dollar$sign",
            "left<angle",
            "right>angle",
            "open(paren",
            "close)paren",
            "back\\slash",
        ]
        for val in forbidden_samples:
            with self.subTest(val=val):
                with self.assertRaises(EnvParseError) as ctx:
                    _parse_unquoted_value(val, 12)
                self.assertIn("line 12", str(ctx.exception))
                self.assertIn(
                    "unquoted value contains forbidden characters", str(ctx.exception)
                )

    # --- Assignment parsing tests ---

    def test_parse_assignment_basic(self) -> None:
        key, val = _parse_assignment("FOO=bar", 1)
        self.assertEqual(key, "FOO")
        self.assertEqual(val, "bar")

    def test_parse_assignment_with_export_prefix(self) -> None:
        key, val = _parse_assignment("export FOO=bar", 1)
        self.assertEqual(key, "FOO")
        self.assertEqual(val, "bar")

        key, val = _parse_assignment("export   BAR_BAZ=123", 2)
        self.assertEqual(key, "BAR_BAZ")
        self.assertEqual(val, "123")

    def test_parse_assignment_empty_value(self) -> None:
        key, val = _parse_assignment("FOO=", 1)
        self.assertEqual(key, "FOO")
        self.assertEqual(val, "")

        key, val = _parse_assignment("FOO=   ", 2)
        self.assertEqual(key, "FOO")
        self.assertEqual(val, "")

    def test_parse_assignment_missing_equals(self) -> None:
        with self.assertRaises(EnvParseError) as ctx:
            _parse_assignment("INVALID_LINE_WITHOUT_EQUALS", 3)
        self.assertIn("line 3", str(ctx.exception))
        self.assertIn("expected KEY=VALUE assignment", str(ctx.exception))

    def test_parse_assignment_preserves_equals_in_value(self) -> None:
        key, val = _parse_assignment('FOO="a=b=c"', 1)
        self.assertEqual(key, "FOO")
        self.assertEqual(val, "a=b=c")

    # --- parse_env_file integration tests ---

    def test_parse_env_file_missing_file_raises_error(self) -> None:
        non_existent = self.test_dir / "does_not_exist.env"
        with self.assertRaises(EnvParseError) as ctx:
            parse_env_file(non_existent)
        self.assertIn("env file not found", str(ctx.exception))

    def test_parse_env_file_directory_raises_error(self) -> None:
        with self.assertRaises(EnvParseError) as ctx:
            parse_env_file(self.test_dir)
        self.assertIn("env file not found", str(ctx.exception))

    def test_parse_env_file_empty(self) -> None:
        env_file = self._create_env_file("")
        result = parse_env_file(env_file)
        self.assertEqual(result, {})

    def test_parse_env_file_comments_and_blank_lines(self) -> None:
        content = """
        # Full line comment
        # Another comment


        """
        env_file = self._create_env_file(content)
        result = parse_env_file(env_file)
        self.assertEqual(result, {})

    def test_parse_env_file_full_workflow(self) -> None:
        content = """# Configuration file
        APP_ENV=production
        PORT=8080
        export HOSTNAME=example.com # inline comment
        DB_NAME="my_database"
        EMPTY_VAR=
        QUOTED_EMPTY=""
        SINGLE_QUOTED='single quoted value'
        COMPLEX_VALUE="token;with&symbols|and<special>chars"
        """
        env_file = self._create_env_file(content)
        result = parse_env_file(env_file)
        expected = {
            "APP_ENV": "production",
            "PORT": "8080",
            "HOSTNAME": "example.com",
            "DB_NAME": "my_database",
            "EMPTY_VAR": "",
            "QUOTED_EMPTY": "",
            "SINGLE_QUOTED": "single quoted value",
            "COMPLEX_VALUE": "token;with&symbols|and<special>chars",
        }
        self.assertEqual(result, expected)

    def test_parse_env_file_reports_correct_line_number(self) -> None:
        content = """# Line 1
        VALID_ONE=1
        # Line 3 is a comment

        INVALID_KEY$=value
        """
        env_file = self._create_env_file(content)
        with self.assertRaises(EnvParseError) as ctx:
            parse_env_file(env_file)
        self.assertIn("line 5", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
