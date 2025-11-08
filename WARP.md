# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Email Security Analysis Pipeline - A self-hosted, containerized email security analysis system that monitors IMAP folders for suspicious messages using multi-layered threat detection.

**Architecture:** Three-layer threat detection system:
- Layer 1: Traditional spam detection (headers, URLs, patterns)
- Layer 2: NLP-based threat detection (social engineering, urgency markers, authority impersonation)
- Layer 3: Media authenticity verification (attachments, deepfake detection)

## Development Commands

### Running the Pipeline

**Background service (recommended):**
```bash
# Install as a launchd daemon (runs automatically on login)
./install_daemon.sh

# Check service status
launchctl list | grep email-security-pipeline

# View logs in real-time
tail -f ~/Library/Logs/email-security-pipeline/pipeline.out
tail -f logs/email_security.log

# Stop the service
launchctl stop com.abhimehrotra.email-security-pipeline

# Start the service
launchctl start com.abhimehrotra.email-security-pipeline

# Uninstall the service
./uninstall_daemon.sh
```

**Local development (manual):**
```bash
# Activate virtual environment (if using)
source venv/bin/activate  # or ./venv/bin/python3

# Run the pipeline
python3 src/main.py

# Run with custom config file
python3 src/main.py path/to/config.env
```

**Docker deployment:**
```bash
# Build the image
docker-compose build

# Start the pipeline
docker-compose up -d

# View logs in real-time
docker-compose logs -f email-security-pipeline

# Stop the pipeline
docker-compose down

# Restart after config changes
docker-compose restart
```

### Configuration & Testing

**Setup configuration:**
```bash
# Create .env from template
cp .env.example .env

# Edit configuration (use nano or preferred editor)
nano .env

# Run setup script (interactive)
./setup.sh
```

**Test configuration:**
```bash
# Run configuration test suite
python3 test_config.py

# Test with connection checks (verifies IMAP connectivity)
python3 test_config.py --test-connections

# Quick validation without connection tests
python3 test_config.py
```

### Logs & Monitoring

**View logs:**
```bash
# Local deployment
tail -f logs/email_security.log

# Docker deployment
docker-compose logs -f
docker-compose logs -f email-security-pipeline

# View last 100 lines
tail -n 100 logs/email_security.log
```

**Check container health:**
```bash
# View container status
docker ps

# Health check
docker inspect --format='{{.State.Health.Status}}' email-security-pipeline
```

## Code Architecture

### Main Orchestrator (`src/main.py`)

**EmailSecurityPipeline** class coordinates all analysis modules:
- Initializes all analyzers and ingestion manager
- Runs continuous monitoring loop (configurable interval)
- Orchestrates three-layer analysis for each email
- Generates threat reports and triggers alerts
- Handles graceful shutdown and signal handling

**Analysis flow per email:**
1. Fetch emails via EmailIngestionManager
2. Run Layer 1: SpamAnalyzer
3. Run Layer 2: NLPThreatAnalyzer  
4. Run Layer 3: MediaAuthenticityAnalyzer
5. Generate unified ThreatReport
6. Send alerts via AlertSystem

### Configuration System (`src/utils/config.py`)

**Dataclass-based configuration** with validation:
- `EmailAccountConfig`: Per-account IMAP settings (Gmail, Outlook, Proton Mail)
- `AnalysisConfig`: Thresholds and feature toggles for all three analysis layers
- `AlertConfig`: Alert channel configuration and threat thresholds
- `SystemConfig`: Logging, intervals, rate limiting, and resource limits

**Important:** Config validation happens at startup. Invalid configurations will prevent the pipeline from running.

### Email Ingestion (`src/modules/email_ingestion.py`)

**EmailIngestionManager** handles multi-account IMAP connections:
- Maintains separate IMAP clients per account
- Implements rate limiting between operations
- Parses email headers, body, and attachments
- Returns `EmailData` objects for analysis

**Key methods:**
- `initialize_clients()`: Establishes IMAP connections for all enabled accounts
- `fetch_all_emails(max_emails)`: Retrieves unread emails from all accounts/folders
- `close_all_connections()`: Cleanup on shutdown

**Note:** Uses rate_limit_delay (default: 1s) between IMAP operations to prevent server throttling.

### Analysis Modules

**SpamAnalyzer** (`src/modules/spam_analyzer.py`):
- Header analysis (SPF, DKIM validation)
- URL reputation checking
- Pattern matching for known spam indicators
- Returns SpamAnalysisResult with risk score

**NLPThreatAnalyzer** (`src/modules/nlp_analyzer.py`):
- Social engineering pattern detection
- Urgency and psychological trigger identification
- Authority impersonation detection
- Linguistic manipulation analysis
- Returns NLPAnalysisResult with threat score

**MediaAuthenticityAnalyzer** (`src/modules/media_analyzer.py`):
- Attachment file type validation
- Magic byte verification against declared MIME types
- Size anomaly detection
- Deepfake indicator analysis (heuristic-based)
- Returns MediaAnalysisResult with threat score

**Important:** Transformers/ML models are optional dependencies. By default, analyzers use rule-based heuristics. Uncomment transformer dependencies in requirements.txt to enable advanced ML models.

### Alert System (`src/modules/alert_system.py`)

**AlertSystem** dispatches alerts through multiple channels:
- Console notifications (stdout)
- Webhook POST requests (JSON payload)
- Slack notifications (webhook integration)

**ThreatReport generation:**
- Combines results from all three analysis layers
- Calculates overall threat score (weighted average)
- Determines risk level (LOW/MEDIUM/HIGH/CRITICAL) based on thresholds
- Generates actionable recommendations

### Project Structure

```
email-security-pipeline/
├── src/
│   ├── main.py                    # Main orchestrator
│   ├── modules/
│   │   ├── email_ingestion.py     # IMAP client & email parsing
│   │   ├── spam_analyzer.py       # Layer 1: Spam detection
│   │   ├── nlp_analyzer.py        # Layer 2: NLP threat detection
│   │   ├── media_analyzer.py      # Layer 3: Media authenticity
│   │   └── alert_system.py        # Alert & notification system
│   └── utils/
│       └── config.py               # Configuration management
├── launchd/                        # Background service configuration
│   ├── com.abhimehrotra.email-security-pipeline.plist  # Launch agent
│   └── README.md                  # Daemon documentation
├── logs/                           # Runtime logs (created automatically)
├── data/                           # Optional database storage
├── tests/                          # Test files (currently empty)
├── .env                            # Configuration (DO NOT COMMIT)
├── .env.example                    # Configuration template
├── requirements.txt                # Python dependencies
├── test_config.py                  # Configuration test suite
├── setup.sh                        # Interactive setup script
├── install_daemon.sh               # Daemon installer
├── uninstall_daemon.sh             # Daemon uninstaller
├── Dockerfile                      # Multi-stage Docker build
└── docker-compose.yml              # Docker Compose configuration
```

## Daemon Setup (Recommended)

The pipeline can run as a background service using macOS's native `launchd` system. This provides automatic startup on login and restart on crashes.

### Installation

**Prerequisites:**
- Valid `.env` configuration
- Passing configuration tests (`python3 test_config.py`)

**Install the daemon:**
```bash
./install_daemon.sh
```

The installer will:
1. Validate your configuration
2. Create log directory at `~/Library/Logs/email-security-pipeline/`
3. Install launch agent to `~/Library/LaunchAgents/`
4. Start the service automatically

### Daemon Features

**Automatic behavior:**
- ✅ Starts automatically on login
- ✅ Restarts automatically if it crashes
- ✅ Runs with lower CPU priority (nice level 5)
- ✅ Throttled restart (60 second minimum between restarts)
- ✅ Won't restart on clean exits (manual stop)

**Benefits over manual execution:**
- No need to keep terminal open
- Survives system reboots
- Automatic crash recovery
- Centralized log management
- Lower resource priority (doesn't impact system performance)

### Managing the Daemon

**Check status:**
```bash
launchctl list | grep email-security-pipeline
# Output shows: PID, status code, label
```

**View logs:**
```bash
# Live monitoring
tail -f ~/Library/Logs/email-security-pipeline/pipeline.out
tail -f ~/Library/Logs/email-security-pipeline/pipeline.err
tail -f logs/email_security.log

# View recent logs
cat ~/Library/Logs/email-security-pipeline/pipeline.out
```

**Control the service:**
```bash
# Stop (manual, won't auto-restart)
launchctl stop com.abhimehrotra.email-security-pipeline

# Start
launchctl start com.abhimehrotra.email-security-pipeline

# Restart (reload configuration)
launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline

# Disable (won't start on login)
launchctl unload ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist

# Re-enable
launchctl load ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
```

**Uninstall:**
```bash
./uninstall_daemon.sh
# Stops service and removes launch agent
# Logs are preserved for review
```

### Daemon Configuration

The launch agent is configured via: `launchd/com.abhimehrotra.email-security-pipeline.plist`

**Key settings:**
- **Label**: `com.abhimehrotra.email-security-pipeline`
- **Working Directory**: `/Users/abhimehrotra/Documents/dev/email-security-pipeline`
- **Python**: `/opt/homebrew/bin/python3`
- **Logs**: `~/Library/Logs/email-security-pipeline/`
- **Auto-start**: Enabled (`RunAtLoad`)
- **Auto-restart**: On crash only (`KeepAlive`)
- **Throttle**: 60 seconds between restart attempts
- **Priority**: Nice level 5 (lower than normal processes)

### Troubleshooting Daemon

**Service won't start:**
```bash
# Check error logs
cat ~/Library/Logs/email-security-pipeline/pipeline.err

# Test configuration manually
python3 test_config.py --test-connections

# Verify plist syntax
plutil ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
```

**Service keeps restarting:**
```bash
# Check for errors in logs
tail -50 ~/Library/Logs/email-security-pipeline/pipeline.err

# Check for connection issues
tail -50 logs/email_security.log | grep -i error

# Verify .env credentials are valid
python3 test_config.py --test-connections
```

**Configuration changes not taking effect:**
```bash
# Restart the service to reload .env
launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline

# Or stop and start
launchctl stop com.abhimehrotra.email-security-pipeline
launchctl start com.abhimehrotra.email-security-pipeline
```

**Compare with maintenance system:**
- Your maintenance scripts use similar launchd configuration
- Located at: `/Users/abhimehrotra/Documents/dev/personal-config/maintenance/launchd/`
- Pattern follows your existing `com.abhimehrotra.maintenance.*` services

## Configuration Guidelines

### Required Environment Variables

**Email accounts** (at least one must be enabled):
- Gmail: `GMAIL_ENABLED=true`, `GMAIL_EMAIL`, `GMAIL_APP_PASSWORD`
- Outlook: `OUTLOOK_ENABLED=true`, `OUTLOOK_EMAIL`, `OUTLOOK_APP_PASSWORD`
- Proton Mail: `PROTON_ENABLED=true`, `PROTON_EMAIL`, `PROTON_APP_PASSWORD` (requires Proton Bridge running)

**Analysis thresholds:**
- `SPAM_THRESHOLD=5.0` (lower = more sensitive)
- `NLP_THRESHOLD=0.7` (0.0-1.0 scale)
- `THREAT_LOW=30`, `THREAT_MEDIUM=60`, `THREAT_HIGH=80`

**System settings:**
- `CHECK_INTERVAL=300` (seconds between email checks)
- `MAX_EMAILS_PER_BATCH=50` (max emails per cycle)
- `RATE_LIMIT_DELAY=1` (seconds between IMAP operations)
- `LOG_LEVEL=INFO` (DEBUG|INFO|WARNING|ERROR)

### Email Provider Setup

**Gmail:**
1. Enable IMAP: Settings → Forwarding and POP/IMAP
2. Generate app password: Google Account → Security → App passwords
3. Use 16-character app password (NOT regular password)
4. Status: ✅ Fully supported and working

**Outlook:**

**⚠️ CRITICAL UPDATE (November 2024):**

Microsoft discontinued app password support for personal Outlook accounts (outlook.com, hotmail.com, live.com, msn.com) as of October 1, 2024.

- ❌ **Personal Outlook accounts**: App passwords NO LONGER WORK with IMAP
- ✅ **Microsoft 365 Business accounts**: May still work (depends on tenant configuration)
- ℹ️ **Current status**: Personal Outlook is NOT SUPPORTED by this pipeline
- 🔧 **Alternative**: OAuth2 implementation required (not yet available)

**Recommended action:** Use Gmail or Proton Mail instead. Set `OUTLOOK_ENABLED=false` in `.env`.

See `OUTLOOK_TROUBLESHOOTING.md` for complete details.

**Proton Mail:**
1. Install and run Proton Mail Bridge application
2. Bridge provides localhost IMAP server (127.0.0.1:1143)
3. Use Bridge-generated password from Bridge interface, NOT your Proton account password
4. Bridge must be running whenever pipeline is active
5. Status: ✅ Fully supported and working
6. Configuration: Server is `127.0.0.1`, Port is `1143`

### Security Requirements

**CRITICAL:** Never commit `.env` file to version control. It's already in `.gitignore`.

**Credential validation:** The pipeline validates that `.env` doesn't contain example values at startup. If you see "appears to contain example values" error, update your credentials.

**File permissions:** Set restrictive permissions on `.env`:
```bash
chmod 600 .env
```

**App passwords:** Always use app-specific passwords, never your main account password. Enable 2FA on all email accounts.

## Development Guidelines

### Adding Custom Analysis Rules

Extend analyzers by modifying pattern lists:

**Spam patterns** (`spam_analyzer.py`):
```python
SPAM_KEYWORDS = [
    # Add custom patterns here
    r'\b(your-custom-pattern)\b',
]
```

**NLP threat indicators** (`nlp_analyzer.py`):
```python
URGENCY_MARKERS = [
    # Add urgency phrases
    "your custom urgency phrase",
]
```

### Enabling Advanced ML Models

1. Uncomment transformer dependencies in `requirements.txt`:
```txt
transformers==4.35.0
torch==2.1.0
sentencepiece==0.1.99
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Models will auto-load on first run (may take time to download)

### Adding New Alert Channels

Extend `AlertSystem` class in `alert_system.py`:

```python
def _custom_alert(self, report: ThreatReport):
    """Your custom alert implementation"""
    # Add notification logic here
    pass
```

Update `send_alert()` method to call your custom alert.

## Testing Approach

**Configuration testing:**
Run `test_config.py` before first use to validate:
- Configuration file loading
- Module imports
- Analyzer initialization
- IMAP connection tests (optional)

**Manual testing workflow:**
1. Send test email with suspicious characteristics
2. Wait for check interval (default: 5 minutes)
3. Review logs for threat detection
4. Verify alerts triggered correctly

**Test email patterns:**
- Subject: "URGENT! You've won $1,000,000!"
- Include suspicious shortened URLs (bit.ly, etc.)
- Add urgency language ("Act now!", "Within 24 hours")
- Test with attachments (check media analysis)

## Troubleshooting

### Connection Issues

**Gmail/Outlook authentication failures:**
- Verify IMAP enabled in account settings
- Regenerate app password
- Check for typos in `.env` (no spaces in app password)
- Verify 2FA is enabled

**Proton Mail connection issues:**
- Ensure Proton Bridge is running
- Verify Bridge credentials in `.env`
- Check Bridge is set to port 1143 (default)
- Bridge must run on same machine as pipeline

**"No emails detected":**
- Verify folder names are correct (case-sensitive)
- Emails must be marked as "unread" (pipeline monitors UNSEEN flag)
- Check `MAX_EMAILS_PER_BATCH` if you have many emails
- Review logs for IMAP fetch errors

### Docker Issues

**Build failures:**
- Ensure `.env` file exists (won't be copied into image)
- Check Docker daemon is running
- Verify sufficient disk space

**Container exits immediately:**
- Check logs: `docker-compose logs email-security-pipeline`
- Verify `.env` has valid credentials
- Ensure no port conflicts

### Performance Issues

**Slow processing:**
- Reduce `MAX_EMAILS_PER_BATCH` to process fewer emails per cycle
- Increase `RATE_LIMIT_DELAY` if hitting IMAP rate limits
- Disable unused analysis layers in configuration
- Consider disabling deepfake detection for faster processing

**High resource usage:**
- Adjust Docker resource limits in `docker-compose.yml`
- Disable ML models if not needed
- Increase `CHECK_INTERVAL` to reduce frequency

## Important Notes

**Credentials:** This pipeline requires app-specific passwords for email accounts. Never use your main account passwords.

**IMAP limitations:** The pipeline monitors unread emails only. Emails must be unread to be analyzed.

**Rate limiting:** IMAP servers enforce rate limits. Default `RATE_LIMIT_DELAY=1` prevents throttling. Increase if experiencing connection issues.

**Outlook:** Personal Outlook accounts (outlook.com, hotmail.com, live.com) are NOT supported due to Microsoft's discontinuation of app password authentication (October 2024). OAuth2 implementation is required but not yet available.

**Proton Mail:** Requires Bridge application running locally. Bridge provides localhost IMAP server (127.0.0.1:1143). Works perfectly when Bridge is active.

**ML models:** Transformer models (NLP) are optional but recommended for production. Without them, rule-based heuristics are used.

**Database:** Database integration is planned but not yet implemented. Current version doesn't persist analysis results.

**Folder monitoring:** Configure which folders to monitor per account via `*_FOLDERS` variables. Default: INBOX for all accounts.

## Quick Reference

**Install as daemon (recommended):** `./install_daemon.sh`

**Start pipeline:** 
- Daemon: `launchctl start com.abhimehrotra.email-security-pipeline`
- Manual: `python3 src/main.py`
- Docker: `docker-compose up -d`

**View logs:** 
- Daemon: `tail -f ~/Library/Logs/email-security-pipeline/pipeline.out`
- Pipeline: `tail -f logs/email_security.log`
- Docker: `docker-compose logs -f`

**Check status:** `launchctl list | grep email-security-pipeline`

**Test config:** `python3 test_config.py`

**Stop pipeline:** 
- Daemon: `launchctl stop com.abhimehrotra.email-security-pipeline`
- Manual: Ctrl+C
- Docker: `docker-compose down`

**Uninstall daemon:** `./uninstall_daemon.sh`

**Config location:** `.env` (root directory)

**Default check interval:** 300 seconds (5 minutes)
