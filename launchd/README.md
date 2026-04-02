# Launchd Configuration

This directory contains the macOS `launchd` configuration for running the Email Security Pipeline as a background service via Docker.

## Files

- `com.abhimehrotra.email-security-pipeline.plist` - Launch agent configuration (manages Docker container)
- `shutdown.sh` - Graceful shutdown script for Docker Compose

## Installation

**Note**: The LaunchAgent now manages the Docker container, not the Python script directly. Ensure Docker is running before installation.

### Manual Installation (Recommended for Docker Setup)

```bash
# Create log directory
mkdir -p ~/Library/Logs/email-security-pipeline

# Copy plist
cp launchd/com.abhimehrotra.email-security-pipeline.plist ~/Library/LaunchAgents/

# Load the launch agent
launchctl load ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist
```

## Configuration

The launch agent is configured to:

- **Auto-start**: Starts on login via Docker Compose
- **Auto-restart**: Restarts if Docker process exits (with 60s throttle)
- **Working directory**: Project root
- **Logs**: `~/Library/Logs/email-security-pipeline/` (LaunchAgent logs)
- **Container logs**: `docker compose logs -f` (application logs)
- **Priority**: Nice level 5 (lower than normal)

**Note**: The LaunchAgent manages the Docker container, not Python directly. This ensures the containerized environment is used.

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
