# Quick Reference Guide

## 🚀 Quick Start

### Run the Pipeline

**Using Virtual Environment (Recommended for Testing):**

```bash
./venv/bin/python3 src/main.py
```

**Using Docker (Recommended for Production):**

```bash
docker-compose up -d
docker-compose logs -f
```

### Stop the Pipeline

**Virtual Environment:**

```bash
# Press Ctrl+C in the terminal
```

**Docker:**

```bash
docker-compose down
```

## 🧪 Testing

### Run Configuration Tests

```bash
./venv/bin/python3 test_config.py
```

### Test IMAP Connections

```bash
./venv/bin/python3 test_config.py --test-connections
```

## 📊 Monitoring

### View Logs

```bash
# Real-time logs
tail -f logs/email_security.log

# Last 100 lines
tail -n 100 logs/email_security.log

# Search for errors
grep ERROR logs/email_security.log
```

### Docker Logs

```bash
# All logs
docker-compose logs

# Follow logs
docker-compose logs -f

# Last 100 lines
docker-compose logs --tail=100
```

## ⚙️ Configuration

### Edit Configuration

```bash
nano .env
# or
vim .env
```

### Key Settings

- `CHECK_INTERVAL`: How often to check for emails (seconds)
- `THREAT_LOW/MEDIUM/HIGH`: Threat score thresholds
- `LOG_LEVEL`: DEBUG, INFO, WARNING, ERROR
- `ALERT_CONSOLE`: Enable/disable console alerts

### Update Credentials

```bash
# Edit .env file
nano .env

# Or use setup script
./setup.sh
```

## 🔧 Troubleshooting

### Connection Issues

- Check credentials in `.env` file
- Verify IMAP is enabled for your email provider
- Test connection: `./venv/bin/python3 test_config.py --test-connections`

### Outlook Issues

- See `OUTLOOK_TROUBLESHOOTING.md` for detailed steps
- Verify app password is correct
- Check IMAP is enabled in Outlook settings

### Log Analysis

```bash
# View recent errors
grep ERROR logs/email_security.log | tail -20

# View connection issues
grep "connection" logs/email_security.log | tail -20

# View threat detections
grep "SECURITY ALERT" logs/email_security.log
```

## 📁 Important Files

- `.env` - Configuration file (credentials)
- `logs/email_security.log` - Application logs
- `test_config.py` - Configuration test script
- `OUTLOOK_TROUBLESHOOTING.md` - Outlook connection guide
- `FUTURE_ENHANCEMENTS.md` - Enhancement roadmap

## 🎯 Common Tasks

### Change Check Interval

```bash
# Edit .env file
CHECK_INTERVAL=600  # Check every 10 minutes
```

### Enable Slack Alerts

```bash
# Edit .env file
ALERT_SLACK_ENABLED=true
ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Adjust Threat Thresholds

```bash
# Edit .env file
THREAT_LOW=20
THREAT_MEDIUM=50
THREAT_HIGH=75
```

### Disable an Email Account

```bash
# Edit .env file
OUTLOOK_ENABLED=false  # Disable Outlook
```

## 📚 Documentation

- `README.md` - Project overview
- `QUICKSTART.md` - Detailed setup guide
- `ENV_SETUP.md` - Credential setup guide
- `ANALYSIS_REPORT.md` - Analysis and fixes report
- `FUTURE_ENHANCEMENTS.md` - Enhancement roadmap

## 🆘 Getting Help

1. Check the troubleshooting guides
2. Review log files for errors
3. Run test script to diagnose issues
4. Check GitHub issues (if open source)

---

**Last Updated:** 2024-11-07
