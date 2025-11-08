# Quick Start Guide

Get your Email Security Pipeline up and running in 5 minutes!

## Step 1: Get Your Email Credentials

### Gmail
1. Go to https://myaccount.google.com/security
2. Enable 2-Step Verification if not already enabled
3. Go to "App passwords" section
4. Create app password for "Mail" → "Other (Custom name)"
5. Save the 16-character password

### Outlook/Hotmail

**⚠️ WARNING: Personal Outlook accounts (outlook.com, hotmail.com, live.com) do NOT support app passwords as of October 2024.**

**Skip this section** unless you have a Microsoft 365 Business account. Use Gmail or Proton Mail instead.

**For Microsoft 365 Business accounts only:**
1. Go to https://account.microsoft.com/security
2. Go to "Advanced security options"
3. Under "App passwords", create new password
4. Select "Mail" as the app
5. Save the generated password

See `OUTLOOK_TROUBLESHOOTING.md` for more information.

## Step 2: Setup the Pipeline

### Using Docker (Recommended)

```bash
# Navigate to project directory
cd ~/Documents/dev/email-security-pipeline

# Copy environment template
cp .env.example .env

# Edit configuration (use nano or your preferred editor)
nano .env
```

**Update these critical fields:**
```env
GMAIL_ENABLED=true
GMAIL_EMAIL=your-actual-email@gmail.com
GMAIL_APP_PASSWORD=your-16-char-app-password
```

**Build and run:**
```bash
# Build the Docker image
docker-compose build

# Start the pipeline
docker-compose up -d

# View logs
docker-compose logs -f
```

### Using Python Locally

```bash
# Navigate to project directory
cd ~/Documents/dev/email-security-pipeline

# Install dependencies
# Install dependencies
python3 -m pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
nano .env  # Update your credentials

# Run the pipeline
python3 src/main.py
```

## Step 3: Test the System

Send yourself a test email with some spam-like characteristics:

**Subject:** URGENT! You've won $1,000,000! Act now!

**Body:**
```
Dear Winner,

Congratulations! You have been selected to receive $1,000,000!

Click here immediately to claim your prize: http://bit.ly/fake-link

This is an urgent matter. You must respond within 24 hours or your prize will expire!

Best regards,
The Prize Committee
```

Within 5 minutes (default check interval), you should see an alert!

## Step 4: Monitor and Adjust

### View Logs

**Docker:**
```bash
docker-compose logs -f email-security-pipeline
```

**Local:**
```bash
tail -f logs/email_security.log
```

### Adjust Sensitivity

Edit `.env` to make detection more or less sensitive:

**More Sensitive (catches more threats, may have false positives):**
```env
SPAM_THRESHOLD=3.0
NLP_THRESHOLD=0.5
THREAT_LOW=20
```

**Less Sensitive (fewer false positives, may miss some threats):**
```env
SPAM_THRESHOLD=7.0
NLP_THRESHOLD=0.8
THREAT_LOW=40
```

## Step 5: Configure Alerts

### Enable Slack Notifications

1. Create Slack webhook: https://api.slack.com/messaging/webhooks
2. Update `.env`:
   ```env
   ALERT_SLACK_ENABLED=true
   ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
   ```
3. Restart pipeline:
   ```bash
   docker-compose restart  # For Docker
   # OR press Ctrl+C and restart for local
   ```

### Enable Webhook Alerts

Update `.env`:
```env
ALERT_WEBHOOK_ENABLED=true
ALERT_WEBHOOK_URL=https://your-webhook-endpoint.com/alerts
```

## Troubleshooting

### "Authentication failed"
- Double-check your app password (no spaces)
- Ensure IMAP is enabled in your email settings
- Try regenerating the app password

### "No emails detected"
- Check folder names are correct (case-sensitive)
- Verify emails are marked as "unread"
- Ensure IMAP permissions are granted

### "Connection timeout"
- Check firewall settings
- Verify network connectivity
- Ensure IMAP ports are not blocked (993 for Gmail/Outlook)

### "Module not found" errors
- Ensure you're running from project root
- Verify all dependencies are installed: `pip install -r requirements.txt`
- Check Python version: `python3 --version` (should be 3.11+)

## Next Steps

1. **Review README.md** for detailed configuration options
2. **Customize detection rules** in `src/modules/` files
3. **Set up multiple email accounts** by adding more account configs
4. **Integrate with your monitoring system** using webhooks
5. **Star the project on GitHub** if you find it useful!

## Getting Help

- Check logs first: `docker-compose logs` or `tail -f logs/email_security.log`
- Review the full README.md for detailed documentation
- Open an issue on GitHub for bugs or feature requests

---

**Security Reminder:** Never commit your `.env` file to version control!
