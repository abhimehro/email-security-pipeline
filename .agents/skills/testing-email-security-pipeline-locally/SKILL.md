---
name: Testing the Email Security Pipeline locally
description: How to run the email-security-pipeline config validation, startup, and diagnostic scripts without real IMAP/SMTP credentials.
---

## Devin Secrets Needed
- None for config/allowlist validation. Real IMAP/SMTP credentials are required only to test an actual mailbox fetch.

## One-liner

```bash
python3 -m src.main test_envs/allowed.env
```

## Common gotchas

- The file `src/app_runner.py` is imported by `src/main.py`; it does **not** have a `__main__` guard, so `python3 -m src.app_runner` exits silently.
- `diagnose_docker_connectivity.py` lives at the repo root, not in `scripts/`.
- `scripts/check_mail_connectivity.py` calls `load_dotenv()` and reads `.env` from the current working directory.
- `diagnose_docker_connectivity.py` calls `load_dotenv(".env")` and also reads the repo-root `.env`.
- `scripts/diagnose_connectivity.py` does not call `load_dotenv()` itself; it constructs `Config()` which loads the configured env file.
- Blank `*_IMAP_SERVER` / `*_SMTP_SERVER` values are treated as falsy and fall back to provider defaults (`imap.gmail.com` / `smtp.gmail.com` for Gmail, etc.).

## Minimal allowed-host `.env`

Use a fake Gmail account to exercise the allowlist gate without leaking credentials:

```text
GMAIL_ENABLED=true
GMAIL_EMAIL=test@example.com
GMAIL_IMAP_SERVER=imap.gmail.com
GMAIL_IMAP_PORT=993
GMAIL_SMTP_SERVER=smtp.gmail.com
GMAIL_SMTP_PORT=465
GMAIL_APP_PASSWORD=<FAKE_PASSWORD>
GMAIL_FOLDERS=INBOX

OUTLOOK_ENABLED=false
PROTON_ENABLED=false

# (include the rest of the analysis/alert/system defaults from .env.example)
```

With this file at `test_envs/allowed.env`, run:

```bash
python3 -m src.main test_envs/allowed.env
```

It should pass `Config.validate()`, print `🚀 Starting pipeline...`, and then fail on Gmail authentication. The pipeline must never start if `GMAIL_IMAP_SERVER` is set to a host outside `ALLOWED_MAIL_SERVER_HOSTS`.

## Fixture templates for SSRF gate verification

Create these under `test_envs/` (do not commit them; `.env` is git-ignored, but `*.env` fixtures may not be).

`test_envs/disallowed_imap.env` — same as `allowed.env` but with:

```text
GMAIL_IMAP_SERVER=169.254.169.254
```

`test_envs/disallowed_smtp.env` — same as `allowed.env` but with:

```text
GMAIL_SMTP_SERVER=internal.evil.com
```

`test_envs/blank.env` — same as `allowed.env` but with:

```text
GMAIL_IMAP_SERVER=
GMAIL_SMTP_SERVER=
```

## Verify the SSRF gate without clobbering the real `.env`

Run the scripts from a scratch directory that contains only the fixture so the real repo-root `.env` is untouched:

```bash
mkdir -p /tmp/esp-test && cd /tmp/esp-test

# Copy the fixture and any needed source references; source stays in the repo
# 1. Pipeline with disallowed IMAP host — should exit 1 before "Starting pipeline"
python3 -m src.main test_envs/disallowed_imap.env

# 2. Connectivity script with blank IMAP/SMTP — should fall back to defaults
#    (run from repo root so the script finds src/; use a temporary .env copy)
(
  cd /tmp/esp-test
  cp /path/to/repo/test_envs/blank.env .env
  /path/to/repo/scripts/check_mail_connectivity.py
  rm -f .env
)

# 3. Diagnostic scripts with disallowed host
(
  cd /tmp/esp-test
  cp /path/to/repo/test_envs/disallowed_imap.env .env
  /path/to/repo/scripts/diagnose_connectivity.py test@example.com
  /path/to/repo/diagnose_docker_connectivity.py
  rm -f .env
)
```

## Unit tests

These tests do not require network access or credentials:

```bash
python3 -m pytest tests/test_mail_server_validation.py -v
```

## What "success" looks like

- Disallowed hosts: generic `IMAP/SMTP host '...' is not in the allowed server list` error, no password printed, no network connection attempted.
- Allowed hosts: validation passes and the app/script proceeds to an authentication failure (or a successful connection if real credentials are supplied).
