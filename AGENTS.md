# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

Email Security Analysis Pipeline — a Python-based email security system that monitors IMAP mailboxes and runs multi-layer threat detection (spam, NLP, media analysis). See `README.md` for full details.

### Running tests

```bash
python3 -m pytest        # all 208 tests; no external services or credentials needed
python3 -m pytest -v     # verbose output
```

Tests mock all IMAP connections and external services; no `.env` file is required.

### Linting

```bash
python3 -m pre_commit run --all-files
```

Note: the repo has pre-existing lint issues (trailing whitespace, EOF fixes, case-conflict in `.Jules`/`.jules` dirs, `.bandit` config parse error). These are not regressions.

### Running the application

The pipeline requires a `.env` file with IMAP credentials (see `.env.example`). To start:

```bash
cp .env.example .env   # then edit with real credentials
python3 src/main.py
```

Without valid IMAP credentials the pipeline will fail at the connection step. For local development without credentials, you can exercise the analysis modules directly by importing from `src.modules`.

### Key gotchas

- **`_get_terminal_width` bug**: The `AlertSystem._console_clean_report` method calls `self._get_terminal_width()` which does not exist. This causes an `AttributeError` when the pipeline tries to display console alerts. This is a pre-existing bug.
- **ML dependencies not installed by default**: `torch`, `transformers`, `sentencepiece` are in `requirements.txt` but excluded from `requirements-ci.txt`. The NLP analyzer falls back to regex-based pattern matching when these are absent.
- **PATH for pip-installed scripts**: User-installed pip scripts land in `~/.local/bin`. Ensure `PATH` includes this directory (the update script handles it).
- **Dependencies**: Use `requirements-ci.txt` for development; `requirements.txt` pulls in multi-GB ML libraries.
