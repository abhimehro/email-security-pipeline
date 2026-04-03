# Launchd Configuration

This directory contains the macOS `launchd` configuration for running the Email Security Pipeline as a background service via Docker Compose with the `colima` Docker context.

## Files

- `com.abhimehrotra.email-security-pipeline.plist` - LaunchAgent configuration
- `start-email-security-pipeline.sh` - Wrapper that starts Colima if needed, waits for Docker, and runs Docker Compose in detached mode
- `shutdown.sh` - Graceful shutdown helper

## Prerequisites

```bash
brew install colima docker docker-compose
brew services start colima
docker context use colima
```

The Docker CLI must be able to run both of these successfully before installing the LaunchAgent:

```bash
docker --context colima info
docker compose version
```

## Installation

```bash
chmod +x install_daemon.sh
./install_daemon.sh
```

The installer copies the plist into `~/Library/LaunchAgents/`, patches it for your local home directory and repo path, and loads it with `launchctl bootstrap`.

## Behavior

The LaunchAgent:

- starts on login
- calls `launchd/start-email-security-pipeline.sh`
- ensures Colima is started
- waits until `docker --context colima info` succeeds
- runs `docker --context colima compose -f docker-compose.yml up -d --remove-orphans`
- writes LaunchAgent logs to `~/Library/Logs/email-security-pipeline/`

## Management Commands

```bash
# Check LaunchAgent status
launchctl print gui/$(id -u)/com.abhimehrotra.email-security-pipeline

# Restart the LaunchAgent
launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline

# Disable the LaunchAgent
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist

# Re-enable the LaunchAgent
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.abhimehrotra.email-security-pipeline.plist

# Check container state
cd ~/dev/email-security-pipeline
docker --context colima compose ps

# Follow container logs
docker --context colima compose logs -f
```

## Troubleshooting

### LaunchAgent loads but the container is not running

```bash
tail -f ~/Library/Logs/email-security-pipeline/pipeline.err
docker --context colima compose ps
docker --context colima compose logs --tail=100
```

### Docker works in terminal but not from launchd

Make sure the plist includes Homebrew in `PATH` and that the wrapper uses the `colima` context explicitly.

### After uninstalling Docker Desktop

If `docker compose` stops working, make sure `~/.docker/config.json` includes the Homebrew plugin directory:

```json
{
  "cliPluginsExtraDirs": ["/opt/homebrew/lib/docker/cli-plugins"]
}
```

And verify:

```bash
docker compose version
```
