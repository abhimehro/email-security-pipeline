"""Functional tests for PR automation scripts and the load_gh_token helper."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec: B404
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

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


def _stubbed_env(tmp: Path) -> dict[str, str]:
    """Return an isolated environment with a stubbed gh on PATH."""
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    log = tmp / "gh_calls.log"
    _write_gh_stub(bin_dir, log)
    env = _base_env(tmp)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    return env


def _run_with_stub(
    script: Path,
    args: list[str],
    env_overrides: dict[str, str] | None = None,
    pre_run: Callable[[Path, dict[str, str]], Path | None] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, str]:
    """Run a script with an isolated HOME, stubbed gh, and optional pre-run setup."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        env = _stubbed_env(tmp_path)
        if env_overrides:
            env.update(env_overrides)
        actual_script = script
        if pre_run:
            maybe_script = pre_run(tmp_path, env)
            if maybe_script is not None:
                actual_script = maybe_script
        result = _run(["bash", str(actual_script), *args], cwd=ROOT, env=env)
        log = tmp_path / "gh_calls.log"
        calls = log.read_text(encoding="utf-8") if log.exists() else ""
        return result, tmp_path, calls


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
        result, _, _ = _run_with_stub(
            LOAD_GH_TOKEN,
            [],
            {"GH_STUB_AUTH_TOKEN": token},
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, f"{token}\n")
        self.assertEqual(result.stderr, "")

    def test_env_file_fallback(self) -> None:
        token = _token("file")

        def _write_env_file(tmp_path: Path, env: dict[str, str]) -> None:
            env_file = tmp_path / "GH_TOKEN.env"
            env_file.write_text(f"GH_TOKEN={token}\n", encoding="utf-8")
            env_file.chmod(0o600)
            env["GH_TOKEN_ENV_FILE"] = str(env_file)

        result, _, _ = _run_with_stub(
            LOAD_GH_TOKEN,
            [],
            {"GH_STUB_AUTH_STATUS_FAIL": "1"},
            pre_run=_write_env_file,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, f"{token}\n")
        self.assertEqual(result.stderr, "")

    def test_fails_when_no_token_resolved(self) -> None:
        result, _, _ = _run_with_stub(
            LOAD_GH_TOKEN,
            [],
            {"GH_STUB_AUTH_STATUS_FAIL": "1"},
        )
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
    def test_callers_do_not_source_the_helper(self) -> None:
        for script in (CLOSE_PRS, FIX_DRAFTS):
            with self.subTest(script=script.name):
                content = script.read_text(encoding="utf-8")
                self.assertNotRegex(content, r"(?m)^\s*source\s+.*load_gh_token\.sh")
                self.assertNotRegex(content, r"(?m)^\s*\.\s+.*load_gh_token\.sh")
                self.assertIn("load_gh_token.sh", content)

    def test_close_prs_reaches_pr_close(self) -> None:
        token = _token("close")
        result, _, calls = _run_with_stub(
            CLOSE_PRS,
            ["--repo", "owner/repo", "123", "456"],
            {"GH_TOKEN": token},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("pr close "), 2)
        self.assertRegex(calls, r"pr close --repo owner/repo --comment [^\n]+ 123\b")
        self.assertRegex(calls, r"pr close --repo owner/repo --comment [^\n]+ 456\b")

    def test_close_prs_helper_failure_prevents_gh_calls(self) -> None:
        result, _, calls = _run_with_stub(
            CLOSE_PRS,
            ["--repo", "owner/repo", "123"],
            {"GH_STUB_AUTH_STATUS_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("pr close", calls)

    def test_close_prs_empty_token_prevents_gh_calls(self) -> None:
        def _install_empty_helper(tmp_path: Path, env: dict[str, str]) -> Path:
            script_copy = tmp_path / "close_prs.sh"
            shutil.copy(CLOSE_PRS, script_copy)
            fake_helper = tmp_path / "load_gh_token.sh"
            fake_helper.write_text(
                "#!/usr/bin/env bash\nprintf '\\n'\nexit 0\n",
                encoding="utf-8",
            )
            fake_helper.chmod(0o755)
            return script_copy

        result, _, calls = _run_with_stub(
            CLOSE_PRS,
            ["--repo", "owner/repo", "123"],
            pre_run=_install_empty_helper,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("pr close", calls)

    def test_fix_drafts_reaches_pr_ready_and_merge(self) -> None:
        token = _token("draft")
        result, _, calls = _run_with_stub(
            FIX_DRAFTS,
            ["owner/repo", "123"],
            {"GH_TOKEN": token},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pr ready 123 --repo owner/repo", calls)
        self.assertIn(
            "pr merge 123 --repo owner/repo --squash --delete-branch",
            calls,
        )

    def test_fix_drafts_helper_failure_prevents_gh_calls(self) -> None:
        result, _, calls = _run_with_stub(
            FIX_DRAFTS,
            ["owner/repo", "123"],
            {"GH_STUB_AUTH_STATUS_FAIL": "1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("pr ready", calls)
        self.assertNotIn("pr merge", calls)

    def test_fix_drafts_empty_token_prevents_gh_calls(self) -> None:
        def _install_empty_helper(tmp_path: Path, env: dict[str, str]) -> Path:
            script_copy = tmp_path / "fix_drafts.sh"
            shutil.copy(FIX_DRAFTS, script_copy)
            fake_helper = tmp_path / "load_gh_token.sh"
            fake_helper.write_text(
                "#!/usr/bin/env bash\nprintf '\\n'\nexit 0\n",
                encoding="utf-8",
            )
            fake_helper.chmod(0o755)
            return script_copy

        result, _, calls = _run_with_stub(
            FIX_DRAFTS,
            ["owner/repo", "123"],
            pre_run=_install_empty_helper,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("pr ready", calls)
        self.assertNotIn("pr merge", calls)


if __name__ == "__main__":
    unittest.main()
