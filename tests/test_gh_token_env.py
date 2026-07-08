"""Security tests for safe env-file parsing used by close_prs.sh."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
HELPER = SCRIPTS / "gh_token_env.py"

sys.path.insert(0, str(SCRIPTS))

from gh_token_env import EnvParseError, parse_env_file  # noqa: E402


class TestGhTokenEnvParser(unittest.TestCase):
    def test_parses_simple_assignment(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("GH_TOKEN=abc123\n")
            path = Path(handle.name)

        try:
            self.assertEqual(parse_env_file(path), {"GH_TOKEN": "abc123"})
        finally:
            path.unlink()

    def test_rejects_command_injection_line(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write('GH_TOKEN=safe\n$(touch /tmp/pwned)\n')
            path = Path(handle.name)

        try:
            with self.assertRaises(EnvParseError):
                parse_env_file(path)
        finally:
            path.unlink()

    def test_rejects_shell_command_disguised_as_key(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("GH_TOKEN=$(id)\n")
            path = Path(handle.name)

        try:
            with self.assertRaises(EnvParseError):
                parse_env_file(path)
        finally:
            path.unlink()

    def test_allows_quoted_token_values(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write('GH_TOKEN="ghp_abc-def_123"\n')
            path = Path(handle.name)

        try:
            self.assertEqual(
                parse_env_file(path), {"GH_TOKEN": "ghp_abc-def_123"}
            )
        finally:
            path.unlink()

    def test_cli_get_does_not_execute_malicious_file(self) -> None:
        marker = Path(tempfile.gettempdir()) / "gh_token_env_pwned_marker"
        if marker.exists():
            marker.unlink()

        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write(f'GH_TOKEN=ok\n$(touch "{marker}")\n')
            path = Path(handle.name)

        try:
            proc = subprocess.run(
                [sys.executable, str(HELPER), "--get", "GH_TOKEN", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(marker.exists())
        finally:
            path.unlink()
            if marker.exists():
                marker.unlink()


class TestClosePrsScript(unittest.TestCase):
    def test_does_not_source_external_env_files(self) -> None:
        script = SCRIPTS / "close_prs.sh"
        content = script.read_text(encoding="utf-8")
        self.assertNotRegex(content, r"(?m)^\s*source\s+")
        self.assertNotRegex(content, r"(?m)^\s*\.\s+")
        self.assertIn("gh_token_env.py", content)


if __name__ == "__main__":
    unittest.main()
