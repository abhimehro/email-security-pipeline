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
- `scripts/check_mail_connectivity.py`, `scripts/diagnose_connectivity.py`, and `diagnose_docker_connectivity.py` all call `load_dotenv()` with no path argument, so they read `.env` from the current working directory.
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

With this file, `python3 -m src.main allowed.env` should pass `Config.validate()`, print `🚀 Starting pipeline...`, and then fail on Gmail authentication. The pipeline must never start if `GMAIL_IMAP_SERVER` is set to a host outside `ALLOWED_MAIL_SERVER_HOSTS`.

## Verify the SSRF gate

```bash
# Should exit 1 before "Starting pipeline" with an allowlist error
python3 -m src.main disallowed_imap.env

# Should fall back to defaults when IMAP/SMTP are blank
cp blank.env .env
python3 scripts/check_mail_connectivity.py
rm -f .env

# Should reject disallowed hosts in diagnostics
cp disallowed_imap.env .env
python3 scripts/diagnose_connectivity.py test@example.com
python3 diagnose_docker_connectivity.py
rm -f .env
```

## Unit tests

```bash
python3 -m pytest tests/test_mail_server_validation.py -v
```

## What "success" looks like

- Disallowed hosts: generic `IMAP/SMTP host '...' is not in the allowed server list` error, no password printed, no network connection attempted.
- Allowed hosts: validation passes and the app/script proceeds to an `Invalid credentials` error from the public Gmail server.
