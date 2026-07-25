"""Functional tests for PR automation scripts and the load_gh_token helper."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
LOAD_GH_TOKEN = SCRIPTS / "load_gh_token.sh"
CLOSE_PRS = SCRIPTS / "close_prs.sh"
FIX_DRAFTS = SCRIPTS / "fix_drafts.sh"


def _run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run a subprocess and capture output; wrapper for test isolation."""
    return subprocess.run(args, capture_output=True, text=True, **kwargs)  # nosec


def _token(label: str) -> str:
    """Return a deterministic-looking but non-hardcoded test token."""
    return f"test_{label}_{os.urandom(4).hex()}"


def _write_gh_stub(bin_dir: Path, log: Path) -> None:
    """Create a fake gh executable that logs non-auth commands."""
    stub = bin_dir / "gh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'GH_STUB_LOG="{log}"\n'
        'case "$1 $2" in\n'
        '  "auth status")\n'
        "    if [[ -n ${GH_STUB_AUTH_STATUS_FAIL:-} ]]; then\n"
        "      exit 1\n"
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        '  "auth token")\n'
        "    if [[ -n ${GH_STUB_AUTH_TOKEN:-} ]]; then\n"
        '      printf "%s\\n" "${GH_STUB_AUTH_TOKEN}"\n'
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  *)\n"
        '    printf "%s " "gh" >> "$GH_STUB_LOG"\n'
        '    for arg in "$@"; do\n'
        '      printf "%s " "$arg" >> "$GH_STUB_LOG"\n'
        "    done\n"
        '    printf "\\n" >> "$GH_STUB_LOG"\n'
        "    ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)


def _base_env(tmp: Path) -> dict[str, str]:
    """Return an isolated environment for a subprocess test run."""
    env = os.environ.copy()
    env.pop("BASH_ENV", None)
    env.pop("GH_TOKEN", None)
    env.pop("GH_TOKEN_ENV_FILE", None)
    env["HOME"] = str(tmp / "home")
    return env


class TestLoadGhToken(unittest.TestCase):
    def test_prints_existing_env_token(self) -> None:
        token = _token("env")
        with tempfile.TemporaryDirectory() as tmp:
            env = _base_env(Path(tmp))
            env["GH_TOKEN"] = token
            result = _run(["bash", str(LOAD_GH_TOKEN)], cwd=ROOT, env=env)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, f"{token}\n")
            self.assertEqual(result.stderr, "")

    def test_gh_auth_token_fallback(self) -> None:
        token = _token("ghp")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            log = tmp_path / "gh_calls.log"
            _write_gh_stub(bin_dir, log)
            env = _base_env(tmp_path)
            env["GH_STUB_AUTH_TOKEN"] = token
            env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
            result = _run(["bash", str(LOAD_GH_TOKEN)], cwd=ROOT, env=env)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, f"{token}\n")
            self.assertEqual(result.stderr, "")

    def test_env_file_fallback(self) -> None:
        token = _token("file")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            log = tmp_path / "gh_calls.log"
            _write_gh_stub(bin_dir, log)
            env_file = tmp_path / "GH_TOKEN.env"
            env_file.write_text(f"GH_TOKEN={token}\n", encoding="utf-8")
            env_file.chmod(0o600)
            env = _base_env(tmp_path)
            env["GH_TOKEN_ENV_FILE"] = str(env_file)
            env["GH_STUB_AUTH_STATUS_FAIL"] = "1"
            env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
            result = _run(["bash", str(LOAD_GH_TOKEN)], cwd=ROOT, env=env)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, f"{token}\n")
            self.assertEqual(result.stderr, "")

    def test_fails_when_no_token_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            log = tmp_path / "gh_calls.log"
            _write_gh_stub(bin_dir, log)
            env = _base_env(tmp_path)
            env["GH_STUB_AUTH_STATUS_FAIL"] = "1"
            env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
            result = _run(["bash", str(LOAD_GH_TOKEN)], cwd=ROOT, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("GH_TOKEN is not configured", result.stderr)

    def test_fails_loudly_when_sourced(self) -> None:
        result = _run(
            ["bash", "-c", 'source "$1"', "_", str(LOAD_GH_TOKEN)],
            cwd=ROOT,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("must be executed, not sourced", result.stderr)


class TestPrAutomationScripts(unittest.TestCase):
    def _stubbed_env(self, tmp: Path) -> dict[str, str]:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        log = tmp / "gh_calls.log"
        _write_gh_stub(bin_dir, log)
        env = _base_env(tmp)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
        return env

    def test_callers_do_not_source_the_helper(self) -> None:
        for script in (CLOSE_PRS, FIX_DRAFTS):
            with self.subTest(script=script.name):
                content = script.read_text(encoding="utf-8")
                self.assertNotRegex(content, r"(?m)^\s*source\s+.*load_gh_token\.sh")
                self.assertNotRegex(content, r"(?m)^\s*\.\s+.*load_gh_token\.sh")
                self.assertIn("load_gh_token.sh", content)

    def test_close_prs_reaches_pr_close(self) -> None:
        token = _token("close")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._stubbed_env(tmp_path)
            env["GH_TOKEN"] = token
            result = _run(
                ["bash", str(CLOSE_PRS), "--repo", "owner/repo", "123", "456"],
                cwd=ROOT,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            log = tmp_path / "gh_calls.log"
            self.assertTrue(log.exists())
            calls = log.read_text(encoding="utf-8")
            self.assertEqual(calls.count("pr close "), 2)
            self.assertRegex(
                calls, r"pr close --repo owner/repo --comment [^\n]+ 123\b"
            )
            self.assertRegex(
                calls, r"pr close --repo owner/repo --comment [^\n]+ 456\b"
            )

    def test_close_prs_helper_failure_prevents_gh_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._stubbed_env(tmp_path)
            env["GH_STUB_AUTH_STATUS_FAIL"] = "1"
            result = _run(
                ["bash", str(CLOSE_PRS), "--repo", "owner/repo", "123"],
                cwd=ROOT,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            log = tmp_path / "gh_calls.log"
            if log.exists():
                calls = log.read_text(encoding="utf-8")
                self.assertNotIn("pr close", calls)

    def test_close_prs_empty_token_prevents_gh_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Copy close_prs.sh into a temp dir and shadow its helper with an
            # executable that returns an empty token successfully.
            script_copy = tmp_path / "close_prs.sh"
            shutil.copy(CLOSE_PRS, script_copy)
            fake_helper = tmp_path / "load_gh_token.sh"
            fake_helper.write_text(
                "#!/usr/bin/env bash\nprintf '\\n'\nexit 0\n",
                encoding="utf-8",
            )
            fake_helper.chmod(0o755)
            env = self._stubbed_env(tmp_path)
            result = _run(
                ["bash", str(script_copy), "--repo", "owner/repo", "123"],
                cwd=ROOT,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            log = tmp_path / "gh_calls.log"
            if log.exists():
                self.assertNotIn("pr close", log.read_text(encoding="utf-8"))

    def test_fix_drafts_reaches_pr_ready_and_merge(self) -> None:
        token = _token("draft")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._stubbed_env(tmp_path)
            env["GH_TOKEN"] = token
            result = _run(
                ["bash", str(FIX_DRAFTS), "owner/repo", "123"],
                cwd=ROOT,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            log = tmp_path / "gh_calls.log"
            self.assertTrue(log.exists())
            calls = log.read_text(encoding="utf-8")
            self.assertIn("pr ready 123 --repo owner/repo", calls)
            self.assertIn(
                "pr merge 123 --repo owner/repo --squash --delete-branch",
                calls,
            )

    def test_fix_drafts_helper_failure_prevents_gh_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env = self._stubbed_env(tmp_path)
            env["GH_STUB_AUTH_STATUS_FAIL"] = "1"
            result = _run(
                ["bash", str(FIX_DRAFTS), "owner/repo", "123"],
                cwd=ROOT,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            log = tmp_path / "gh_calls.log"
            if log.exists():
                calls = log.read_text(encoding="utf-8")
                self.assertNotIn("pr ready", calls)
                self.assertNotIn("pr merge", calls)

    def test_fix_drafts_empty_token_prevents_gh_calls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            script_copy = tmp_path / "fix_drafts.sh"
            shutil.copy(FIX_DRAFTS, script_copy)
            fake_helper = tmp_path / "load_gh_token.sh"
            fake_helper.write_text(
                "#!/usr/bin/env bash\nprintf '\\n'\nexit 0\n",
                encoding="utf-8",
            )
            fake_helper.chmod(0o755)
            env = self._stubbed_env(tmp_path)
            result = _run(
                ["bash", str(script_copy), "owner/repo", "123"],
                cwd=ROOT,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            log = tmp_path / "gh_calls.log"
            if log.exists():
                self.assertNotIn("pr ready", log.read_text(encoding="utf-8"))
                self.assertNotIn("pr merge", log.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
