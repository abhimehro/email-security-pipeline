# Launchd Configuration

This directory contains the macOS `launchd` configuration for running the Email Security Pipeline as a background service.

## Files

- `com.abhimehrotra.email-security-pipeline.plist` - Launch agent configuration

## Installation

Run the installation script from the project root:

```bash
./install_daemon.sh
```

This will:
1. Validate your configuration
2. Copy the plist to `~/Library/LaunchAgents/`
3. Start the service automatically

## Manual Installation

If you prefer to install manually:

```bash
# Copy plist
cp launchd/com.abhimehrotra.email-security-pipeline.plist ~/Library/LaunchAgents/

# Load the launch agent
launchctl load ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
```

## Configuration

The launch agent is configured to:
- **Auto-start**: Starts on login
- **Auto-restart**: Restarts if it crashes (with 60s throttle)
- **Working directory**: Project root
- **Logs**: `~/Library/Logs/email-security-pipeline/`
- **Priority**: Nice level 5 (lower than normal)

## Management Commands

```bash
# Check status
launchctl list | grep email-security-pipeline

# Stop service
launchctl stop com.abhimehrotra.email-security-pipeline

# Start service
launchctl start com.abhimehrotra.email-security-pipeline

# Restart (reload config)
launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline

# Disable (won't start on login)
launchctl unload ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist

# Re-enable
launchctl load ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
```

## Logs

View logs in real-time:
```bash
tail -f ~/Library/Logs/email-security-pipeline/pipeline.out
tail -f ~/Library/Logs/email-security-pipeline/pipeline.err
```

## Uninstallation

Run the uninstall script:
```bash
./uninstall_daemon.sh
```

Or manually:
```bash
launchctl unload ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
rm ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
```

## Troubleshooting

**Service won't start:**
- Check error logs: `cat ~/Library/Logs/email-security-pipeline/pipeline.err`
- Validate config: `python3 test_config.py --test-connections`
- Check plist syntax: `plutil ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist`

**Service keeps restarting:**
- Check for errors: `tail -50 ~/Library/Logs/email-security-pipeline/pipeline.err`
- Verify credentials: `python3 test_config.py --test-connections`

**Config changes not applied:**
- Restart service: `launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline`

## Notes

This follows the same pattern as your maintenance scripts at:
`/Users/abhimehrotra/Documents/dev/personal-config/maintenance/launchd/`
