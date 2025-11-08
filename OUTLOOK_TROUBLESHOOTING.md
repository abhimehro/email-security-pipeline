# Outlook IMAP Connection Troubleshooting Guide

## Current Status

**Issue:** Outlook IMAP connection is failing with "LOGIN failed" error.

**Working Accounts:**

- ✅ Gmail (user@gmail.com) - Connected successfully
- ✅ Proton Mail (user@pm.me) - Connected successfully
- ❌ Outlook (your-email@outlook.com) - Connection failing

## Troubleshooting Steps

### Step 1: Verify App Password

1. **Check App Password Generation:**

   - Go to: https://account.microsoft.com/security
   - Navigate to: Security → Advanced security options → App passwords
   - Verify the app password was created for "Mail" or "Other (Custom name)"
   - Ensure the app password is exactly 16 characters (no spaces)

2. **Generate New App Password:**
   - Delete the old app password
   - Create a new app password
   - Copy it immediately (you won't see it again)
   - Update `.env` file with the new password

### Step 2: Enable IMAP in Outlook

1. **Check IMAP Settings:**

   - Go to: https://outlook.live.com/mail/
   - Click Settings (gear icon) → View all Outlook settings
   - Go to: Mail → Sync email
   - Ensure "Let devices and apps use IMAP" is **enabled**

2. **Verify POP/IMAP Access:**
   - Some accounts may have POP/IMAP disabled by default
   - Enable both POP and IMAP access if available

### Step 3: Check Two-Factor Authentication

1. **Verify 2FA is Enabled:**

   - Go to: https://account.microsoft.com/security
   - Check if Two-factor authentication is enabled
   - App passwords only work if 2FA is enabled

2. **If 2FA is Not Enabled:**
   - Enable 2FA first
   - Then generate an app password

### Step 4: Account Security Settings

1. **Check Security Defaults:**

   - Some Microsoft accounts have "Security defaults" enabled
   - This may block app password authentication
   - You may need to disable security defaults (if you have admin access)

2. **Check for Account Restrictions:**
   - Some accounts may have restrictions on third-party app access
   - Check account security settings for any blocks

### Step 5: Test Connection Manually

You can test the IMAP connection manually using a command-line tool:

```bash
# Using openssl (if available)
openssl s_client -connect outlook.office365.com:993 -quiet

# Then try:
# a LOGIN abhimehro@outlook.com <app-password>
```

### Step 6: Alternative Authentication Methods

If app passwords continue to fail, consider:

1. **OAuth2 Authentication:**

   - More secure than app passwords
   - Requires application registration with Microsoft
   - Better long-term solution

2. **Modern Authentication:**
   - Some accounts require modern authentication
   - May need to use Microsoft Graph API instead of IMAP

## Configuration Check

Verify your `.env` file has the correct settings:

```env
OUTLOOK_ENABLED=true
OUTLOOK_EMAIL=abhimehro@outlook.com
OUTLOOK_IMAP_SERVER=outlook.office365.com
OUTLOOK_IMAP_PORT=993
OUTLOOK_APP_PASSWORD=your-16-char-app-password
OUTLOOK_FOLDERS=INBOX,Junk
```

**Important:**

- No spaces in the app password
- Server is `outlook.office365.com` (not `imap-mail.outlook.com`)
- Port is `993` (SSL/TLS)

## Common Issues & Solutions

### Issue: "LOGIN failed" Error

**Possible Causes:**

1. App password is incorrect or expired
2. IMAP is not enabled for the account
3. 2FA is not enabled
4. Account security settings are blocking access
5. Password has extra spaces or characters

**Solutions:**

1. Generate a new app password
2. Enable IMAP in Outlook settings
3. Enable 2FA if not already enabled
4. Check account security settings
5. Verify password in `.env` file (no spaces, exact match)

### Issue: "Connection Timeout"

**Possible Causes:**

1. Firewall blocking port 993
2. Network connectivity issues
3. Outlook server is down

**Solutions:**

1. Check firewall settings
2. Test network connectivity
3. Verify Outlook service status

### Issue: "SSL Certificate Error"

**Possible Causes:**

1. System clock is incorrect
2. SSL certificate issues
3. Proxy interference

**Solutions:**

1. Sync system clock
2. Check SSL certificate validity
3. Configure proxy settings if needed

## Testing Connection

After making changes, test the connection:

```bash
./venv/bin/python3 test_config.py --test-connections
```

## Next Steps

1. **Try the troubleshooting steps above**
2. **Generate a new app password if needed**
3. **Verify IMAP is enabled in Outlook settings**
4. **Test the connection again**
5. **If still failing, consider OAuth2 authentication**

## Alternative: Use Without Outlook

The pipeline works perfectly with Gmail and Proton Mail. You can:

1. **Disable Outlook temporarily:**

   ```env
   OUTLOOK_ENABLED=false
   ```

2. **Run with Gmail and Proton Mail only:**
   - Both accounts are working correctly
   - You can add Outlook later when the issue is resolved

## Support Resources

- **Microsoft Support:** https://support.microsoft.com/
- **Outlook IMAP Settings:** https://support.microsoft.com/en-us/office/pop-imap-and-smtp-settings-8361e398-8af4-4e97-b147-6c6c4ac95353
- **App Passwords:** https://support.microsoft.com/en-us/account-billing/using-app-passwords-with-apps-that-don-t-support-two-step-verification-5896ed9b-4263-e681-128a-a6f2979a7944

---

**Last Updated:** 2024-11-07
