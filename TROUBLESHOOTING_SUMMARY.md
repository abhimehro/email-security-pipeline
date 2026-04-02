# Email Security Pipeline Troubleshooting Summary

**Date**: April 2, 2026  
**Status**: ✅ .env detection fixed | ⚠️ Email authentication issues remain

## What We Fixed

### 1. Docker .env Detection Issue ✅
**Problem**: Container couldn't find `/app/.env` file  
**Root Cause**: `docker-compose.yml` was loading environment **variables** via `env_file`, but the Python app needed the actual `.env` **file** to exist  
**Solution**: Added `.env` as a read-only volume mount in `docker-compose.yml`

**Changes Made**:
- `docker-compose.yml`: Added `.env:/app/.env:ro` volume mount
- `docker-compose.yml`: Added `extra_hosts` for `host.docker.internal` to reach Proton Bridge
- `launchd/com.abhimehrotra.email-security-pipeline.plist`: Updated to manage Docker container
- `launchd/shutdown.sh`: Created graceful shutdown script
- `.env`: Updated `PROTON_IMAP_SERVER` from `127.0.0.1` to `host.docker.internal`
- `.env`: Removed spaces from Gmail app password
- `.env`: Added `PROTON_VERIFY_SSL=false` for self-signed cert

**Verification**: ✅ Container now successfully reads `.env` and loads configuration

---

## Remaining Issues

### Issue 1: Gmail Authentication Failure
**Error**: `[AUTHENTICATIONFAILED] Invalid credentials (Failure)`  
**Current Config**:
- Email: `abhimhrtr@gmail.com`
- App Password: `enmfnbufsdmrdpnf` (spaces removed)
- Server: `imap.gmail.com:993`

**Possible Causes**:
1. App password is expired or revoked
2. App password was copied incorrectly (common with auto-generated passwords)
3. 2-Step Verification was disabled on the account
4. IMAP access is disabled in Gmail settings

**Next Steps**:
```bash
# Regenerate a fresh Gmail app password:
# 1. Visit: https://myaccount.google.com/apppasswords
# 2. Create new password for "Mail" application
# 3. Copy it EXACTLY (all 16 characters, no spaces)
# 4. Update .env:
GMAIL_APP_PASSWORD=<paste-new-password-here>

# Then restart:
docker compose down && docker compose up -d
```

### Issue 2: Proton Mail Bridge SSL Failure
**Error**: `[SSL] record layer failure (_ssl.c:1016)`  
**Current Config**:
- Email: `abhimehro@pm.me`
- Bridge: `host.docker.internal:1143`
- SSL: `PROTON_USE_SSL=true`, `PROTON_VERIFY_SSL=false`

**Analysis**:
- ✅ Bridge IS running on port 1143 (verified with `lsof`)
- ✅ Container can reach `host.docker.internal` (connection attempt succeeds)
- ✅ Config correctly loads `PROTON_VERIFY_SSL=false`
- ❌ SSL handshake fails despite certificate verification being disabled

**Possible Causes**:
1. **TLS version mismatch**: Bridge might use older TLS version, but app enforces TLS 1.2+
2. **Cipher suite incompatibility**: Bridge and app can't agree on encryption
3. **Bridge password incorrect**: Some SSL errors manifest as "record layer failure"
4. **Bridge not fully initialized**: Bridge might still be starting up

**Next Steps to Diagnose**:

**A. Test Proton Bridge directly from host (not Docker)**:
```bash
# Test with openssl to see exact SSL error
openssl s_client -connect 127.0.0.1:1143 -tls1_2

# Test with Python directly
python3 << 'EOF'
import imaplib
import ssl
context = ssl._create_unverified_context()
imap = imaplib.IMAP4_SSL('127.0.0.1', 1143, ssl_context=context)
imap.login('abhimehro@pm.me', 'jsLSzp4stwyTjcOCAcTWTQ')
print("Success!")
EOF
```

**B. Check Proton Bridge logs**:
```bash
# Bridge logs location (macOS):
~/Library/Logs/protonmail/bridge/
# or check Bridge app settings for log location
```

**C. Verify Bridge settings**:
- Open Proton Mail Bridge app
- Check that account `abhimehro@pm.me` is connected
- Verify the bridge password matches `.env` (might need to regenerate)
- Check TLS settings in Bridge preferences

**D. Try temporarily disabling SSL** (test only):
```env
PROTON_USE_SSL=false  # This will use STARTTLS instead
```

---

## Quick Test Commands

### Check current container status
```bash
cd ~/dev/email-security-pipeline
docker compose ps
docker compose logs --tail=30
```

### Verify .env is mounted correctly
```bash
docker compose exec email-security-pipeline cat /app/.env | head -15
```

### Test Gmail credentials manually
```bash
# Generate test script
cat > /tmp/test_gmail.py << 'EOF'
import imaplib
imap = imaplib.IMAP4_SSL('imap.gmail.com', 993)
imap.login('abhimhrtr@gmail.com', 'enmfnbufsdmrdpnf')
print("Gmail: SUCCESS!")
imap.logout()
EOF

python3 /tmp/test_gmail.py
```

### Restart pipeline after .env changes
```bash
docker compose down
docker compose up -d
docker compose logs -f
```

---

## Summary

**Fixed**: ✅ Docker .env detection and mounting  
**Fixed**: ✅ Proton Bridge networking (host.docker.internal)  
**Next**: 🔍 Need to verify/regenerate both Gmail and Proton credentials  

The pipeline infrastructure is now working correctly. The remaining issues are authentication-specific and need credential verification/regeneration.
