"""Security tests for safe env-file parsing used by automation shell scripts."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from io import StringIO
from pathlib import Path
from typing import Iterator


from src.utils.gh_token_cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SCRIPTS = ROOT / "scripts"
HELPER = SCRIPTS / "gh_token_env.py"
SECURE_AUTOMATION_SCRIPTS = (
    SCRIPTS / "close_prs.sh",
    SCRIPTS / "fix_drafts.sh",
)

from src.utils.env_file_parser import EnvParseError, parse_env_file


@contextmanager
def temporary_env_file(content: str) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(content)
        path = Path(handle.name)
    try:
        yield path
    finally:
        path.unlink()


class TestGhTokenEnvParser(unittest.TestCase):
    def test_parses_simple_assignment(self) -> None:
        with temporary_env_file("GH_TOKEN=abc123\n") as path:
            self.assertEqual(parse_env_file(path), {"GH_TOKEN": "abc123"})

    def test_rejects_command_injection_line(self) -> None:
        with temporary_env_file('GH_TOKEN=safe\n$(touch /tmp/pwned)\n') as path:
            with self.assertRaises(EnvParseError):
                parse_env_file(path)

    def test_rejects_shell_command_disguised_as_key(self) -> None:
        with temporary_env_file("GH_TOKEN=$(id)\n") as path:
            with self.assertRaises(EnvParseError):
                parse_env_file(path)

    def test_allows_quoted_token_values(self) -> None:
        with temporary_env_file('GH_TOKEN="ghp_abc-def_123"\n') as path:
            self.assertEqual(
                parse_env_file(path), {"GH_TOKEN": "ghp_abc-def_123"}
            )

    def test_strips_trailing_inline_comments_from_unquoted_values(self) -> None:
        with temporary_env_file("GH_TOKEN=abc123  # local token\n") as path:
            self.assertEqual(parse_env_file(path), {"GH_TOKEN": "abc123"})

    def test_cli_get_does_not_execute_malicious_file(self) -> None:
        marker = Path(tempfile.gettempdir()) / "gh_token_env_pwned_marker"
        if marker.exists():
            marker.unlink()

        with temporary_env_file(f'GH_TOKEN=ok\n$(touch "{marker}")\n') as path:
            proc = subprocess.run(
                [sys.executable, str(HELPER), "--get", "GH_TOKEN", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(marker.exists())



    def test_cli_main_handles_env_parse_error(self) -> None:
        with temporary_env_file("INVALID LINE\n") as path:
            with redirect_stderr(StringIO()) as stderr:
                ret_code = cli_main([str(path)])
                self.assertEqual(ret_code, 1)
                self.assertIn("error:", stderr.getvalue())

class TestAutomationScripts(unittest.TestCase):
    def test_automation_scripts_do_not_source_external_env_files(self) -> None:
        for script in SECURE_AUTOMATION_SCRIPTS:
            with self.subTest(script=script.name):
                content = script.read_text(encoding="utf-8")
                self.assertNotRegex(content, r"(?m)^\s*source\s+.*\.env")
                self.assertNotRegex(content, r"(?m)^\s*\.\s+.*\.env")
                self.assertIn("load_gh_token", content)

    def test_shared_loader_avoids_direct_env_sourcing(self) -> None:
        loader = SCRIPTS / "load_gh_token.sh"
        content = loader.read_text(encoding="utf-8")
        self.assertNotRegex(content, r"(?m)^\s*source\s+.*\.env")
        self.assertIn("gh_token_env.py", content)


if __name__ == "__main__":
    unittest.main()
