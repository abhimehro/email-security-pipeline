# Docker Setup Guide - Email Security Pipeline

## Quick Start

### Build the image

```bash
docker build -t email-security-pipeline:latest .
```

### Production - Run with docker-compose

```bash
docker compose up -d
```

### Development - Hot reload

```bash
docker compose -f docker-compose.dev.yml up
```

### Testing

```bash
docker compose -f docker-compose.test.yml up
```

## File Structure

- **Dockerfile**: Multi-stage build optimized for production
- **docker-compose.yml**: Production configuration with security hardening
- **docker-compose.dev.yml**: Development configuration with code mounts and
  interactive shell
- **docker-compose.test.yml**: Testing configuration
- **.dockerignore**: Excludes unnecessary files from build context

## Security Features

### Dockerfile

- **Multi-stage build**: Reduces final image size by excluding build
  dependencies
- **Non-root user**: Runs as `emailsec` (UID 1000)
- **Minimal base image**: Uses `python:3.13-slim`
- **No pip cache**: `--no-cache-dir` flag reduces layer size
- **Environment variables**: `PYTHONUNBUFFERED` and `PYTHONDONTWRITEBYTECODE`

### docker-compose.yml

- **no-new-privileges**: Prevents privilege escalation
- **read_only root filesystem**: Mount `/tmp` and `/var/tmp` as tmpfs
- **Resource limits**: CPU and memory constraints
- **Health checks**: 5-minute intervals with 3 retries
- **JSON logging**: Structured logs with rotation (10MB max, 3 files)
- **Private network**: Isolated bridge network

## Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Key environment variables:

- `GMAIL_ENABLED`, `OUTLOOK_ENABLED`, `PROTON_ENABLED`: Account selection
- `NLP_ENABLE_ML`: Toggle machine learning threat detection
- `ALERT_*`: Configure alerts (console, webhook, Slack)
- `LOG_LEVEL`, `LOG_FORMAT`: Logging configuration

## Volume Mounts

- `./logs:/app/logs` - Application logs
- `./data:/app/data` - Persistent data (database, cache)
- `./.env:/app/.env:ro` - Environment configuration (read-only, **required for
  application to read .env file**)
- `./src:/app/src` - Application code (dev/test only)

## Networking

Container runs on `email-security-net` bridge network:

```bash
# List network details
docker network inspect email-security-net
```

### Proton Mail Bridge Connection

If using Proton Mail Bridge running on your host machine with implicit SSL
(`PROTON_USE_SSL=true`), you can pin the local self-signed TLS certificate for
secure verification:

- Place your Bridge certificate (e.g. exported from Bridge) in
  `./data/proton-bridge-cert.pem` (mounted via `./data:/app/data`).
- Configure in `.env` (use the IMAP port shown in Bridge):

  ```env
  PROTON_IMAP_SERVER=host.docker.internal
  PROTON_IMAP_PORT=1143
  PROTON_USE_SSL=true
  PROTON_TLS_CA_FILE=data/proton-bridge-cert.pem
  PROTON_TLS_SERVER_HOSTNAME=127.0.0.1
  ```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:521affa1ae31a580c5df61d7f189ee9e7941d909024e2d4e956f38f25c07d7e9 -->

- `PROTON_IMAP_SERVER` is the connection address and must be reachable from the
  container. Colima reachability of a host loopback-only Bridge through
  `host.docker.internal` has not been verified for this guide. Test connectivity
  from the pipeline container with your Colima version and network configuration
  before relying on it; do not assume it forwards to host `127.0.0.1:1143`.
  Docker Desktop uses its own host networking mechanism; its behavior does not
  establish Colima reachability. On native Linux with bridge networking, Bridge
  must listen on a host interface reachable from the container, rather than
  only on host loopback.
- `PROTON_TLS_SERVER_HOSTNAME` controls certificate verification independently
  of the connection address. TLS SNI is sent only for DNS names, not IP literals.
  The certificate must include that hostname or IP (here `127.0.0.1`) in its
  subject alternative name (SAN).

<!-- /coderabbit-ai-generated:v1 -->
- On Linux, a loopback-only Bridge can instead be reached using host networking:
  in a local Compose configuration, set `network_mode: host` on the pipeline
  service and remove that service's `networks` entry. Set
  `PROTON_IMAP_SERVER=127.0.0.1` and use the IMAP port configured in Bridge.
  Keep the TLS CA and verification hostname settings above. Host networking
  shares the host network namespace and removes Docker network isolation; use it
  only when that tradeoff is acceptable. With bridge networking, the
  reachable-interface requirement above still applies.
- If Bridge uses STARTTLS mode, set `PROTON_USE_SSL=false`.

## Health Checks

The container includes a health check that runs every 5 minutes:

```bash
# View health status
docker ps --format "table {{.Names}}\t{{.Status}}"
```

## Logs

### View container logs

```bash
docker logs email-security-pipeline -f
```

### View application logs

```bash
tail -f logs/email_security.log
```

### Structured JSON logs (from docker-compose.yml)

```bash
docker logs email-security-pipeline | jq .
```

## Common Commands

### Start container

```bash
docker compose up -d
docker compose logs -f  # Follow logs
```

### Stop container

```bash
docker compose down
```

### Rebuild image

```bash
docker compose build --no-cache
```

### Run commands in container

```bash
docker compose exec email-security-pipeline python3 -c "import sys; print(sys.version)"
```

### Clean up

```bash
docker compose down -v  # Remove volumes
docker system prune -a  # Remove unused images/containers
```

## Troubleshooting

### Container exits immediately

Check logs:

```bash
docker logs email-security-pipeline
```

### Out of memory

Increase memory limit in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      memory: 2G # Increase from 1G
```

### Permission denied errors

The container runs as non-root (UID 1000). Ensure host directories are writable:

```bash
chmod 755 logs data
```

### Build fails with pip install errors

Try rebuilding without cache:

```bash
docker compose build --no-cache
```

## Production Deployment

For production environments:

1. **Use specific tags**: Instead of `latest`, tag with version numbers
   ```bash
   docker build -t email-security-pipeline:v1.0 .
   docker push your-registry/email-security-pipeline:v1.0
   ```

2. **Scan for vulnerabilities**:
   ```bash
   docker scout cves email-security-pipeline:latest
   ```

3. **Use container orchestration**: Consider Kubernetes or Docker Swarm for
   multi-host deployments

4. **Configure CI/CD**: Automate builds on code pushes using GitHub Actions or
   similar

## Image Metadata

The Docker image includes OCI labels:

- `org.opencontainers.image.title`: Email Security Pipeline
- `org.opencontainers.image.description`: Comprehensive email security analysis
  and threat detection
- `org.opencontainers.image.version`: 1.0

View with:

```bash
docker inspect email-security-pipeline:latest | jq '.[0].Config.Labels'
```

## Local Development (Without Docker)

While Docker remains the canonical path for testing, linting, and validation,
you can set up a local Python venv for rapid iteration and debugging.

### Setup

```bash
# Create and activate venv
python3.13 -m venv .venv
source .venv/bin/activate

# Install runtime and test dependencies
pip install -r requirements.txt -r requirements-dev.txt
```

### Running Tests Locally

```bash
# All tests
pytest

# With coverage report
pytest --cov=src --cov-report=html

# Specific test file
pytest tests/test_threat_scoring.py -v
```

### Limitations

This local setup **does not include**:

- Pre-commit hooks (use `pre-commit run --all-files` in Docker via
  `docker compose exec`)
- Linters and validators (black, pylint, etc.)
- Environment isolation from your system Python

For full validation before pushing, always run
`docker compose -f docker-compose.test.yml up` to match CI behavior exactly.

### Troubleshooting

If pytest cannot find modules:

```bash
export PYTHONPATH=/path/to/repo:$PYTHONPATH
```

If you see import errors on `src/` modules, confirm your venv uses Python 3.13:

```bash
python --version  # Should print 3.13.x
```
