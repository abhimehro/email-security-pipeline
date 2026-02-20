# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Email Security Analysis Pipeline – a self-hosted system that monitors IMAP folders and scores emails for risk using a three-layer analysis stack:
- **Layer 1 – SpamAnalyzer:** headers, URLs, and pattern-based spam heuristics
- **Layer 2 – NLPThreatAnalyzer:** social engineering, urgency, and authority impersonation signals
- **Layer 3 – MediaAuthenticityAnalyzer:** attachment type/size validation and basic deepfake indicators

The core orchestration loop lives in `src/main.py` and continuously ingests unread emails, runs all analyzers, aggregates results into a `ThreatReport`, and dispatches alerts.

---

## Development & Runtime Commands

### 1. Environment & Dependencies

From the repo root:
```bash
# (Optional but recommended) Create and activate a venv
python3 -m venv venv
source venv/bin/activate  # or use ./venv/bin/python3 directly

# Install Python dependencies
python3 -m pip install -r requirements.txt

# Create config from template
cp .env.example .env

# Edit configuration
nano .env  # see README.md, QUICKSTART.md, and ENV_SETUP.md for details
```

For secure/automated `.env` setup with 1Password or Docker secrets, prefer the flows documented in `ENV_SETUP.md`.

### 2. Run the Pipeline

**Local (Python, foreground – best for development):**
```bash
# Using virtualenv interpreter
./venv/bin/python3 src/main.py

# Or system python3 if not using venv
python3 src/main.py
```

You can optionally pass a specific env file path:
```bash
python3 src/main.py path/to/config.env
```

**Docker Compose (recommended for long-running / production-like):**
```bash
# Build image
docker compose build

# Start in background
docker compose up -d

# Follow logs
docker compose logs -f email-security-pipeline

# Stop containers
docker compose down
```

**macOS launchd daemon (background service on login):**
```bash
# Install launch agent (valid .env required)
chmod +x install_daemon.sh
./install_daemon.sh

# Check status
launchctl list | grep email-security-pipeline

# Control lifecycle
launchctl start  com.abhimehrotra.email-security-pipeline
launchctl stop   com.abhimehrotra.email-security-pipeline

# Uninstall daemon
chmod +x uninstall_daemon.sh
./uninstall_daemon.sh
```

Daemon logs are written to `~/Library/Logs/email-security-pipeline/` (see “Logs & Monitoring”). The launchd plist lives in `launchd/com.abhimehrotra.email-security-pipeline.plist` and uses `/opt/homebrew/bin/python3` with this repo as the working directory.

### 3. Configuration Tests & Diagnostics

There is no formal pytest/coverage suite yet; testing is driven by rich diagnostics scripts and manual flows.

**Core configuration & import tests:**
```bash
# Basic configuration, imports, analyzer init, folder parsing
./venv/bin/python3 test_config.py

# Include live IMAP connectivity checks (uses accounts defined in .env)
./venv/bin/python3 test_config.py --test-connections
```

`test_config.py` exercises:
- `.env` presence and `Config` loading/validation
- module imports under `src.utils` and `src.modules.*`
- analyzer and alert-system initialization
- folder parsing logic in `Config._parse_folders`
- optional IMAP connectivity via `EmailIngestionManager`
- JSON-based connectivity diagnostics via `scripts/diagnose_connectivity.py`

**Connectivity diagnostics helpers (when present):**
```bash
# High-level connectivity diagnostics (JSON output)
python3 scripts/diagnose_connectivity.py you@example.com

# IMAP/SMTP NOOP sanity check based on .env
python3 scripts/check_mail_connectivity.py
```

If you add a real unit-test suite under `tests/` (e.g., pytest), document the test runner here and keep `requirements.txt` dev dependencies in sync.

### 4. Logs & Monitoring

**Local run logs:**
```bash
# Stream application log
tail -f logs/email_security.log

# Last 100 lines
tail -n 100 logs/email_security.log

# Basic error/threat inspection
grep ERROR logs/email_security.log | tail -20
grep "SECURITY ALERT" logs/email_security.log || true
```

**Docker logs:**
```bash
# All logs
docker compose logs

# Follow specific service
docker compose logs -f email-security-pipeline

# Last 100 lines
docker compose logs --tail=100 email-security-pipeline
```

**launchd daemon logs (macOS):**
```bash
# Live monitoring
tail -f ~/Library/Logs/email-security-pipeline/pipeline.out
tail -f ~/Library/Logs/email-security-pipeline/pipeline.err

# Recent output
tail -n 100 ~/Library/Logs/email-security-pipeline/pipeline.out
```

For quick command lookups, `QUICK_REFERENCE.md` mirrors most of these snippets in a cheat-sheet format.

---

## Code Architecture Overview

### 1. Orchestration & Entry Point – `src/main.py`

- Defines the `EmailSecurityPipeline` (and related bootstrapping) that:
  - loads configuration via `src.utils.config.Config`
  - initializes analyzers and `EmailIngestionManager`
  - enters the main loop: fetch unread mail → run analyzers → aggregate into `ThreatReport` → dispatch via `AlertSystem`
  - controls check cadence via `SystemConfig.check_interval`
- Responsible for graceful shutdown and connection cleanup.

### 2. Configuration System – `src/utils/config.py`

- Central authority for reading `.env`, validating settings, and exposing typed configuration:
  - `EmailAccountConfig`: provider (Gmail/Outlook/Proton), IMAP host/port, enabled flag, folders, security flags
  - `AnalysisConfig`: thresholds and feature toggles for spam/NLP/media layers
  - `AlertConfig`: console/webhook/Slack toggles + threat score thresholds
  - `SystemConfig`: logging level, check interval, batch sizes, rate limiting, attachment limits
- Important behaviors:
  - rejects obviously example-ish or missing credentials at startup
  - normalizes folder lists via `_parse_folders()` (comma- or newline-delimited strings → `List[str]`)
  - provides `validate()` to catch misconfiguration before the pipeline starts.

When agents change or add env variables, keep `.env.example`, `README.md`, and this section in sync.

### 3. Email Ingestion – `src/modules/email_ingestion.py`

- `EmailIngestionManager` abstracts multi-account IMAP access:
  - one IMAP client per configured `EmailAccountConfig`
  - `initialize_clients()` handles connection setup, error handling, and client registry (`clients: Dict[email, client]`)
  - `fetch_all_emails(max_emails)` pulls unread messages across accounts/folders and yields unified `EmailData` objects
  - `close_all_connections()` gracefully tears down sessions
- Applies `SystemConfig.rate_limit_delay` between IMAP operations to avoid provider throttling.

Any future IMAP provider quirks or OAuth2 flows should be funneled through this layer rather than direct `imaplib` usage elsewhere.

### 4. Analysis Stack – `src/modules/*.py`

- **`spam_analyzer.py` – SpamAnalyzer**
  - Uses header signals (SPF/DKIM/etc.), URL reputation checks, and regex-style content patterns
  - Computes a numeric spam score; configurable via `AnalysisConfig.spam_threshold`
  - Keyword/pattern lists are designed to be safely extendable (see README and existing constants).

- **`nlp_analyzer.py` – NLPThreatAnalyzer**
  - Looks for social engineering cues (urgency, fear, authority, time pressure)
  - Optionally integrates transformer-based models if ML dependencies in `requirements.txt` are uncommented and installed
  - Uses `AnalysisConfig.nlp_threshold` to gate alerts.

- **`media_analyzer.py` – MediaAuthenticityAnalyzer**
  - Validates attachment MIME types vs magic bytes
  - Enforces size and type sanity checks
  - Contains hooks/placeholders for more advanced deepfake/ML-based analysis
  - Controlled via `AnalysisConfig.check_media_attachments` and related toggles.

Each analyzer is designed to be:
- initialized once per process using its slice of `AnalysisConfig`
- pure/stateless per-analysis call where feasible, for testability and later parallelization.

### 5. Alert System – `src/modules/alert_system.py`

- `AlertSystem` is the single sink for emitting `ThreatReport` results:
  - console logging (always available)
  - generic webhook POSTs (JSON payloads)
  - Slack webhook notifications
- Uses thresholds from `AlertConfig` to classify scores as LOW/MEDIUM/HIGH/CRITICAL.
- Intended extension point for new channels:
  - add `_custom_alert()`-style methods
  - wire them into the main `send_alert()` dispatcher.

### 6. Scripts & Tooling

- **`test_config.py`**
  - Standalone diagnostics runner; no external test framework required
  - Designed to quickly surface configuration/import/connection issues in a single invocation.

- **`scripts/diagnose_connectivity.py` / `scripts/check_mail_connectivity.py` (if present)**
  - Narrow tools for IMAP/SMTP reachability, SSL validity, and credential sanity
  - `diagnose_connectivity.py` emits structured JSON intended for both human and programmatic consumption.

- **`launchd/`**
  - `com.abhimehrotra.email-security-pipeline.plist` defines the macOS agent used by `install_daemon.sh`
  - `launchd/README.md` documents the daemon behavior (auto restart, throttling, log paths).

The `tests/` directory currently has no conventional unit tests; treat it as a future home for pytest-style suites.

---

## Provider-Specific Notes (Configuration-Sensitive Behavior)

These points are important for agents interacting with email provider configuration and documentation.

- **Gmail**
  - Fully supported via IMAP + app passwords
  - Setup steps and `.env` examples are in `README.md`, `QUICKSTART.md`, and `ENV_SETUP.md`.

- **Outlook / Hotmail (personal)**
  - As of October 1, 2024, personal Outlook-family accounts **no longer support app passwords for IMAP**.
  - This pipeline does **not** implement OAuth2 yet; personal Outlook is therefore not supported.
  - For Microsoft 365 Business tenants, app passwords may still work; details and caveats live in `OUTLOOK_TROUBLESHOOTING.md` and `README.md`.

- **Proton Mail**
  - Requires Proton Mail Bridge running locally
  - `.env` uses Bridge host/port and Bridge-generated credentials; see `README.md` and `ENV_SETUP.md` for the current recommended values and connectivity sanity-check commands.

When editing provider docs or env variable sets, keep `README.md`, `QUICKSTART.md`, `OUTLOOK_TROUBLESHOOTING.md`, and this section aligned.

---

## Documentation Map (for Agents)

Prefer linking to the existing docs instead of duplicating their content:

- `README.md` – canonical project overview, architecture diagram, configuration reference, and limitations
- `QUICKSTART.md` – 5-minute setup path (credentials → .env → Docker/local run → test email)
- `QUICK_REFERENCE.md` – operational cheat sheet for commands (start/stop, logs, config edits, common tasks)
- `ENV_SETUP.md` – `.env` and secrets management strategies (manual, 1Password CLI, Docker secrets)
- `OUTLOOK_TROUBLESHOOTING.md` – detailed explanation of Outlook auth deprecations and supported scenarios
- `FUTURE_ENHANCEMENTS.md` – roadmap of planned features (OAuth2, DB persistence, dashboard, etc.)
- `ANALYSIS_REPORT.md` / `DOCUMENTATION_UPDATE_SUMMARY.md` / `TEST_RESULTS.md` – historical analysis and documentation/testing state

Agents should generally:
- treat `README.md` + `QUICKSTART.md` as the source of truth for user-facing setup guidance
- use `QUICK_REFERENCE.md` for operational commands instead of re-inventing variants
- update this `WARP.md` only when large-scale architectural or workflow changes occur.
