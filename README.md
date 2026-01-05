# Email Security Analysis Pipeline

A self-hosted, containerized email security analysis system that monitors IMAP folders for suspicious messages using multi-layered threat detection.

## Features

### Multi-Layer Threat Detection

1. **Layer 1: Traditional Spam Detection**
   - Header analysis (SPF, DKIM validation)
   - Content pattern matching
   - URL reputation checking
   - Sender verification

2. **Layer 2: NLP-Based Threat Detection**
   - Social engineering pattern recognition
   - Urgency and psychological trigger detection
   - Authority impersonation identification
   - Linguistic manipulation analysis

3. **Layer 3: Media Authenticity Verification**
   - Attachment file type validation
   - Magic byte verification
   - Size anomaly detection
   - Deepfake indicator analysis (placeholder for ML models)

### Alert & Response System

- Console notifications
- Webhook integration
- Slack notifications
- Customizable threat thresholds
- Actionable threat recommendations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Email Accounts                          │
│          (Gmail, Outlook, Proton Mail via IMAP)            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Email Ingestion Module                         │
│         (IMAP Client + Rate Limiting)                       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Analysis Engine Stack                          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Layer 1: Spam Detection (Headers, URLs, Patterns)   │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │ Layer 2: NLP Threat Detection (Social Engineering)  │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │ Layer 3: Media Authenticity (Attachments, Deepfake) │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│           Alert & Response System                           │
│     (Console, Webhooks, Slack, Threat Reports)             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+ or Docker
- Email account(s) with IMAP access
- App passwords for email accounts (if 2FA enabled)

### Option 1: Docker Deployment (Recommended)

1. **Clone the repository**
   ```bash
   cd ~/Documents/dev
   git clone <repository-url> email-security-pipeline
   cd email-security-pipeline
   ```

2. **Configure environment**
   ```bash
   cp .env.example .env
   nano .env  # Edit with your credentials
   ```

3. **Build and run with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **View logs**
   ```bash
   docker-compose logs -f
   ```

### Option 3: Background Execution (macOS/Darwin)

If you are on macOS, you can run the pipeline as a background service (launchd daemon) that starts automatically on login.

1. **Install the daemon**
   ```bash
   chmod +x install_daemon.sh
   ./install_daemon.sh
   ```

2. **Manage the service**
   ```bash
   # View logs
   tail -f ~/Library/Logs/email-security-pipeline/pipeline.out
   
   # Restart service
   launchctl stop com.abhimehrotra.email-security-pipeline
   launchctl start com.abhimehrotra.email-security-pipeline
   
   # Uninstall daemon
   chmod +x uninstall_daemon.sh
   ./uninstall_daemon.sh
   ```

## Configuration

### Email Account Setup

#### Gmail
1. Enable IMAP: Settings → Forwarding and POP/IMAP → Enable IMAP
2. Generate App Password: Google Account → Security → 2-Step Verification → App passwords
3. Update `.env`:
   ```env
   GMAIL_ENABLED=true
   GMAIL_EMAIL=your-email@gmail.com
   GMAIL_APP_PASSWORD=your-16-char-app-password
   ```

#### Outlook/Hotmail

**⚠️ CRITICAL: Personal Outlook accounts (outlook.com, hotmail.com, live.com, msn.com) NO LONGER support app passwords as of October 1, 2024.**

- **Personal Accounts**: App passwords do NOT work. Requires OAuth2 (not currently supported).
- **Microsoft 365 Business**: May still work with app passwords (depends on tenant configuration).

**For Microsoft 365 Business accounts only:**
1. Enable IMAP: Settings → Sync email → Let devices use IMAP
2. Generate App Password: Account security → Advanced security options → App passwords
3. Update `.env`:
   ```env
   OUTLOOK_ENABLED=true
   OUTLOOK_EMAIL=your-email@outlook.com
   OUTLOOK_APP_PASSWORD=your-app-password
   ```

**Recommendation:** Use Gmail or Proton Mail instead of personal Outlook accounts.

See `OUTLOOK_TROUBLESHOOTING.md` for more details.

#### Proton Mail
1. Install Proton Mail Bridge: https://proton.me/mail/bridge
2. Configure Bridge and get credentials
3. Update `.env` (Bridge ports as currently configured):
   ```env
   PROTON_ENABLED=true
   PROTON_EMAIL=abhimehro@pm.me
   PROTON_IMAP_SERVER=127.0.0.1
   PROTON_IMAP_PORT=143      # Bridge local IMAP; use 1143 if your Bridge expects STARTTLS
   PROTON_APP_PASSWORD=your-bridge-password
   PROTON_FOLDERS=INBOX
   ```
   **Note:** Proton Mail requires the Bridge application running locally; adjust the IMAP port if your Bridge uses 1143/STARTTLS instead of 143/SSL.

#### Connectivity sanity checks (Bridge + Gmail)
```bash
# Proton IMAP (adjust port if needed)
openssl s_client -connect 127.0.0.1:143 -quiet </dev/null | head -5

# Gmail IMAP
openssl s_client -connect imap.gmail.com:993 -quiet </dev/null | head -5
```

### IMAP/SMTP quick check CLI
- Script: `scripts/check_mail_connectivity.py`
- Prereq: `.env` populated (GMAIL_* / PROTON_* vars).
- Run:
  ```bash
  python scripts/check_mail_connectivity.py
  ```
- It issues NOOP on IMAP/SMTP for Gmail and Proton Bridge using your .env settings; no messages are fetched or sent.

### Analysis Configuration

Adjust detection sensitivity in `.env`:

```env
# Layer 1: Spam Detection
SPAM_THRESHOLD=5.0              # Lower = more sensitive
SPAM_CHECK_HEADERS=true
SPAM_CHECK_URLS=true

# Layer 2: NLP Threat Detection
NLP_THRESHOLD=0.7               # 0.0 to 1.0
CHECK_SOCIAL_ENGINEERING=true
CHECK_URGENCY_MARKERS=true
CHECK_AUTHORITY_IMPERSONATION=true

# Layer 3: Media Authenticity
CHECK_MEDIA_ATTACHMENTS=true
DEEPFAKE_DETECTION_ENABLED=true
```

### Alert Configuration

```env
# Console alerts
ALERT_CONSOLE=true

# Webhook alerts
ALERT_WEBHOOK_ENABLED=false
ALERT_WEBHOOK_URL=https://your-webhook-url.com/alerts

# Slack alerts
ALERT_SLACK_ENABLED=false
ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Threat score thresholds
THREAT_LOW=30
THREAT_MEDIUM=60
THREAT_HIGH=80
```

### System Configuration

```env
LOG_LEVEL=INFO                  # DEBUG, INFO, WARNING, ERROR
CHECK_INTERVAL=300              # Seconds between email checks
MAX_EMAILS_PER_BATCH=50        # Max emails to process per cycle
RATE_LIMIT_DELAY=1              # Delay between IMAP operations (seconds)
```

## Project Structure

```
email-security-pipeline/
├── src/
│   ├── main.py                 # Main orchestrator
│   ├── modules/
│   │   ├── email_ingestion.py  # IMAP client & email parsing
│   │   ├── spam_analyzer.py    # Layer 1: Spam detection
│   │   ├── nlp_analyzer.py     # Layer 2: NLP threat detection
│   │   ├── media_analyzer.py   # Layer 3: Media authenticity
│   │   └── alert_system.py     # Alert & notification system
│   └── utils/
│       └── config.py            # Configuration management
├── logs/                        # Application logs
├── data/                        # Optional database
├── .env                         # Configuration (create from .env.example)
├── .env.example                 # Configuration template
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Multi-stage Docker build
├── docker-compose.yml           # Docker Compose configuration
└── README.md                    # This file
```

## Security Considerations

### Credential Management
- **Never** commit `.env` file to version control
- Use app-specific passwords (not account passwords)
- Store credentials securely using environment variables
- Consider using secret management tools (e.g., HashiCorp Vault)

### Docker Security
- Runs as non-root user (`emailsec`)
- Read-only root filesystem
- Resource limits enforced
- Security options enabled (`no-new-privileges`)

### Rate Limiting
- Configurable delays between IMAP operations
- Prevents server throttling/blocking
- Respects email provider limits

## Monitoring & Logs

### View Logs

**Docker:**
```bash
docker-compose logs -f email-security-pipeline
```

**Local:**
```bash
tail -f logs/email_security.log
```

### Log Levels

- **DEBUG**: Detailed analysis scores and decisions
- **INFO**: Email processing and alerts
- **WARNING**: Configuration issues, connection problems
- **ERROR**: Critical failures

## Troubleshooting

### Connection Issues

**Problem:** Can't connect to IMAP server

**Solutions:**
- Verify credentials in `.env`
- Check IMAP is enabled in email account settings
- For Gmail/Outlook: Ensure app password is correctly generated
- For Proton Mail: Verify Bridge is running
- Check firewall/network settings

### Authentication Errors

**Problem:** Login failed

**Solutions:**
- Regenerate app password
- Verify 2FA is properly configured
- Check for account security alerts
- Ensure IMAP access is enabled

### No Emails Detected

**Problem:** Pipeline runs but finds no emails

**Solutions:**
- Check folder names in config (case-sensitive)
- Verify emails exist in monitored folders
- Check email is marked as "unread" (pipeline monitors UNSEEN)
- Increase `MAX_EMAILS_PER_BATCH` if needed

## Advanced Features

### Adding Custom Analysis Rules

Extend `spam_analyzer.py`, `nlp_analyzer.py`, or `media_analyzer.py` with custom patterns:

```python
# Example: Add custom spam keyword
SPAM_KEYWORDS = [
    # ... existing patterns
    r'\b(your-custom-pattern)\b',
]
```

### Integrating ML Models

Uncomment transformer dependencies in `requirements.txt`:

```txt
transformers==4.35.0
torch==2.1.0
sentencepiece==0.1.99
```

Update `nlp_analyzer.py` to load models in `_initialize_model()`.

### Custom Alert Channels

Extend `alert_system.py` with additional notification methods:

```python
def _custom_alert(self, report: ThreatReport):
    # Your custom alert logic
    pass
```

## Performance Tuning

- **Check Interval**: Increase for less frequent checks, reduce load
- **Rate Limit Delay**: Increase if experiencing throttling
- **Batch Size**: Reduce if processing is slow
- **Analysis Layers**: Disable unused layers for faster processing

## Limitations

- **Personal Outlook Accounts**: Not supported due to Microsoft's discontinuation of app password authentication (October 2024). Only OAuth2 is supported, which is not yet implemented.
- **Proton Mail**: Requires Bridge application running locally (Bridge provides localhost IMAP server)
- **Deepfake Detection**: Basic heuristics only; ML models not included
- **Transformer Models**: Not enabled by default (requires additional dependencies)
- **IMAP Only**: Does not support POP3 or proprietary APIs (e.g., Microsoft Graph)

## Future Enhancements

- [ ] **OAuth2 Authentication** for personal Outlook/Microsoft accounts (high priority)
- [ ] Full transformer model integration for NLP analysis
- [ ] Advanced deepfake detection using specialized ML models
- [ ] Database persistence for threat history
- [ ] Web dashboard for monitoring and configuration
- [ ] Email quarantine and automatic remediation
- [ ] Integration with SIEM systems
- [ ] Support for Microsoft Graph API (Exchange/O365)
- [ ] Sandboxed attachment analysis

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions, please open an issue on GitHub.

## Acknowledgments

Built with security and privacy in mind for self-hosted email threat detection.
