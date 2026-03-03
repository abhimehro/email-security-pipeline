# Contributing to Email Security Pipeline

Thank you for your interest in contributing! This guide gives you everything you
need to set up a development environment, run tests and linters, and open a
well-formed pull request.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Development Setup](#development-setup)
3. [Running Tests](#running-tests)
4. [Running the Linter](#running-the-linter)
5. [Running Pre-commit](#running-pre-commit)
6. [Submitting a Pull Request](#submitting-a-pull-request)
7. [Secrets Policy](#secrets-policy)

---

## Prerequisites

| Requirement | Minimum version |
|-------------|-----------------|
| Python      | 3.11            |
| Git         | any recent      |
| Docker *(optional, for integration testing)* | any recent |

> **Note:** The heavy ML libraries (`torch`, `transformers`, `sentencepiece`)
> are intentionally excluded from the CI requirements file. The pipeline
> gracefully falls back to regex-based analysis when they are absent, so you do
> **not** need them for local development or testing.

---

## Development Setup

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/<your-username>/email-security-pipeline.git
cd email-security-pipeline

# 2. Install the lightweight CI dependency set (no multi-GB ML libraries)
python3 -m pip install -r requirements-ci.txt

# 3. Install pre-commit hooks so checks run automatically before each commit
pre-commit install
```

The application reads credentials from a `.env` file at runtime. A template is
provided:

```bash
cp .env.example .env
# Edit .env with your IMAP credentials — see README.md for per-provider details
```

> **Important:** The `.env` file is already listed in `.gitignore`. Never
> remove it from that list, and never commit credentials. See
> [Secrets Policy](#secrets-policy) below.

---

## Running Tests

Tests mock all IMAP connections and external services, so **no `.env` file or
live credentials are required** to run them.

```bash
# Run the full test suite
python3 -m pytest

# Run with verbose output
python3 -m pytest -v

# Run a specific test file
python3 -m pytest tests/test_spam_analyzer.py

# Run with coverage (requires pytest-cov)
python3 -m pip install pytest-cov
python3 -m pytest --cov=src --cov-report=term-missing
```

---

## Running the Linter

The project uses **[Trunk](https://trunk.io/)** as its primary formatting and
linting tool. Trunk manages black (formatting), isort (import sorting), ruff
(linting), bandit (security scanning), and several other checks. This is what
runs in CI (`trunk check --ci`).

**Install Trunk** (one-time):

```bash
# macOS / Linux
curl https://get.trunk.io -fsSL | bash
# or via Homebrew:
brew install trunk-io/formulae/trunk
```

**Run checks locally:**

```bash
# Check only files changed since the last commit (fastest)
trunk check

# Check all files in the repository (matches CI behaviour)
trunk check --all

# Auto-format files (black + isort)
trunk fmt
```

> **Note:** pre-commit (see the next section) runs a separate, complementary
> set of hooks focused on file hygiene and security scanning. It does **not**
> run black, isort, or ruff — those belong to Trunk.

> **Note:** The repository has a small number of pre-existing lint warnings
> (trailing whitespace, EOF issues, case-conflict in `.Jules`/`.jules`
> directories, a `.bandit` config parse warning). These are not regressions and
> do not need to be fixed as part of an unrelated PR.

---

## Running Pre-commit

Pre-commit runs automatically before every `git commit` once installed. It
includes the following hooks:

| Hook | What it checks |
|------|----------------|
| `trailing-whitespace` | Removes trailing spaces |
| `end-of-file-fixer` | Ensures files end with a newline |
| `check-yaml` / `check-json` / `check-toml` | Config file syntax |
| `check-added-large-files` | Blocks files larger than 500 KB |
| `check-merge-conflict` | Detects leftover conflict markers |
| `check-case-conflict` | Prevents files that differ only by case |
| `debug-statements` | Detects accidental `pdb`/`breakpoint()` calls |
| `mixed-line-ending` | Enforces LF line endings |
| `requirements-txt-fixer` | Keeps `requirements*.txt` sorted |
| `bandit` | Security linting for `src/` |
| `python-check-blanket-noqa` | Flags bare `# noqa` without specific codes |
| `python-check-mock-methods` | Detects incorrect mock method names |
| `python-no-eval` | Prevents use of `eval()` |
| `python-no-log-warn` | Flags deprecated `logger.warn()` calls |
| `python-use-type-annotations` | Encourages type hints |

Useful commands:

```bash
# Run on all files manually
pre-commit run --all-files

# Run on specific files
pre-commit run --files src/modules/spam_analyzer.py

# Update hook versions
pre-commit autoupdate

# Skip a specific hook for one commit (use sparingly)
SKIP=bandit git commit -m "your message"

# Bypass all hooks in a genuine emergency (use very sparingly)
git commit --no-verify -m "emergency fix"
```

---

## Submitting a Pull Request

### Branch Naming

Use one of these prefixes followed by a short, hyphen-separated description:

| Prefix | Use for |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation-only changes |
| `chore/` | Maintenance (deps, config, CI) |
| `test/` | Test additions or improvements |
| `perf/` | Performance improvements |
| `refactor/` | Code restructuring without behaviour change |

Examples: `feat/oauth2-outlook`, `fix/media-analyzer-zip-bomb`, `docs/contributing-guide`

### Before Opening the PR

1. Make sure the full test suite passes: `python3 -m pytest`
2. Make sure pre-commit passes: `pre-commit run --all-files`
3. Keep changes focused — one logical change per PR makes review faster.
4. Reference the related issue number in your PR description (e.g. `Closes #42`).

### What to Include in the PR Description

Use the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) provided in
the repository. At a minimum your description should cover:

- **What** was changed and **why**
- The issue or context being addressed
- How the change was tested
- Any security implications (even if none — say so explicitly)
- Any follow-up work that is intentionally out of scope

---

## Secrets Policy

> **TL;DR: Never commit secrets. Use `.env` instead.**

- Credentials, API keys, app passwords, and tokens must **never** appear in
  source code, commit messages, or PR descriptions.
- Copy `.env.example` to `.env` and fill in real values locally. The `.env`
  file is git-ignored and must stay that way.
- If you accidentally commit a secret, rotate/revoke it immediately and then
  contact the maintainer to scrub the git history.
- Use `chmod 600 .env` on Unix systems to restrict file permissions.
- In CI, use GitHub Actions Secrets — never hard-code credentials in workflow
  files.

For more details on deployment security, see [SECURITY.md](SECURITY.md) and
[ENV_SETUP.md](ENV_SETUP.md).
