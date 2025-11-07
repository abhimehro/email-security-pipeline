# Environment File Setup Guide

This guide explains how to securely set up your `.env` file with credentials for the Email Security Pipeline.

## Quick Setup

1. **Copy the example file:**
   ```bash
   cp .env.example .env
   ```

2. **Edit the .env file** with your actual credentials (see options below)

3. **Verify .env is in .gitignore** (it should be by default)

## Credential Management Options

### Option 1: Manual Entry (Simple)

Edit `.env` directly with your credentials:

```bash
nano .env
# or
vim .env
# or use your preferred editor
```

**Pros:**
- Simple and straightforward
- No additional tools required
- Works immediately

**Cons:**
- Credentials stored in plain text on disk
- Requires manual updates when passwords change

### Option 2: 1Password CLI Integration (Recommended)

1Password CLI can securely retrieve credentials and populate your `.env` file.

#### Setup 1Password CLI

1. **Install 1Password CLI:**
   ```bash
   # macOS (Homebrew)
   brew install --cask 1password-cli

   # Or download from: https://developer.1password.com/docs/cli/get-started
   ```

2. **Sign in to 1Password:**
   ```bash
   op signin
   ```

3. **Create a script to populate .env from 1Password:**

   Create a file `setup-env-from-1password.sh`:
   ```bash
   #!/bin/bash
   # Retrieve credentials from 1Password and create .env file

   # Sign in if not already
   op signin

   # Create .env from template
   cp .env.example .env

   # Get credentials from 1Password (adjust item names as needed)
   GMAIL_APP_PASSWORD=$(op item get "Gmail App Password" --field "password")
   OUTLOOK_APP_PASSWORD=$(op item get "Outlook App Password" --field "password")

   # Update .env file
   sed -i '' "s|GMAIL_APP_PASSWORD=.*|GMAIL_APP_PASSWORD=$GMAIL_APP_PASSWORD|" .env
   sed -i '' "s|OUTLOOK_APP_PASSWORD=.*|OUTLOOK_APP_PASSWORD=$OUTLOOK_APP_PASSWORD|" .env

   echo ".env file created with credentials from 1Password"
   ```

4. **Store credentials in 1Password:**
   - Create a new item in 1Password for each email account
   - Store the app password securely
   - Note the item name for use in the script

**Pros:**
- Credentials stored securely in 1Password
- No plain text credentials on disk
- Easy to rotate passwords
- Can be automated

**Cons:**
- Requires 1Password CLI setup
- Requires 1Password account
- Slightly more complex initial setup

### Option 3: Environment Variables (Docker/Production)

For production deployments, use Docker secrets or environment variables:

```yaml
# docker-compose.yml
services:
  email-security-pipeline:
    environment:
      - GMAIL_APP_PASSWORD=${GMAIL_APP_PASSWORD}
      - OUTLOOK_APP_PASSWORD=${OUTLOOK_APP_PASSWORD}
    # OR use secrets
    secrets:
      - gmail_password
      - outlook_password

secrets:
  gmail_password:
    external: true
  outlook_password:
    external: true
```

**Pros:**
- No credential files in container
- Secure for production
- Can use orchestration secrets management

**Cons:**
- More complex setup
- Requires orchestration platform

### Option 4: SSH Configuration with 1Password SSH Agent

If using 1Password's SSH agent integration:

1. **Enable 1Password SSH Agent:**
   ```bash
   # Add to ~/.ssh/config
   Host *
     IdentityAgent ~/Library/Group\ Containers/2BUA8C4S2C.com.1password/t/agent.sock
   ```

2. **Use setup script** that retrieves credentials securely

**Note:** This is primarily for SSH keys, but can be combined with 1Password CLI for app passwords.

## Security Best Practices

1. **Never commit .env to version control**
   - Verify `.env` is in `.gitignore`
   - Use `.env.example` for templates only

2. **Use app-specific passwords**
   - Never use your main email password
   - Generate app passwords for each service
   - Rotate passwords periodically

3. **Restrict file permissions:**
   ```bash
   chmod 600 .env  # Only owner can read/write
   ```

4. **Use secrets management in production**
   - Prefer environment variables or secrets managers
   - Avoid storing credentials in code or config files

5. **Regularly rotate credentials**
   - Update app passwords every 90 days
   - Revoke old app passwords when creating new ones

## Recommended Approach

For **development/local use:**
- Use **Option 1** (Manual Entry) for quick setup
- Or **Option 2** (1Password CLI) for better security

For **production:**
- Use **Option 3** (Environment Variables/Secrets)
- Or orchestration platform secrets (Kubernetes Secrets, AWS Secrets Manager, etc.)

## Troubleshooting

### .env file not found
```bash
cp .env.example .env
# Then edit .env with your credentials
```

### Credentials not working
- Verify app passwords are correct
- Check that IMAP is enabled for your email account
- Verify server and port settings match your provider

### 1Password CLI not working
```bash
# Check if signed in
op account list

# Sign in again if needed
op signin
```

## Example .env File Structure

```env
# Email Account 1: Gmail
GMAIL_ENABLED=true
GMAIL_EMAIL=your-actual-email@gmail.com
GMAIL_IMAP_SERVER=imap.gmail.com
GMAIL_IMAP_PORT=993
GMAIL_APP_PASSWORD=your-16-char-app-password
GMAIL_FOLDERS=INBOX,Spam

# Alert Configuration
ALERT_CONSOLE=true
THREAT_LOW=30
THREAT_MEDIUM=60
THREAT_HIGH=80

# ... (see .env.example for full structure)
```

## Next Steps

1. Set up your `.env` file using one of the options above
2. Test the configuration: `python3 src/main.py` (or use Docker)
3. Review logs to verify email connections are working
4. Adjust threat thresholds based on your needs
