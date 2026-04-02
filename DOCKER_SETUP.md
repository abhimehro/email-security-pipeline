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
- **docker-compose.dev.yml**: Development configuration with code mounts and interactive shell
- **docker-compose.test.yml**: Testing configuration
- **.dockerignore**: Excludes unnecessary files from build context

## Security Features

### Dockerfile
- **Multi-stage build**: Reduces final image size by excluding build dependencies
- **Non-root user**: Runs as `emailsec` (UID 1000)
- **Minimal base image**: Uses `python:3.11-slim`
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
- `./.env:/app/.env:ro` - Environment configuration (read-only, **required for application to read .env file**)
- `./src:/app/src` - Application code (dev/test only)

## Networking

Container runs on `email-security-net` bridge network:
```bash
# List network details
docker network inspect email-security-net
```

### Proton Mail Bridge Connection

If using Proton Mail Bridge running on your host machine, the container uses `host.docker.internal` to reach services on your Mac:

- Bridge runs on host: `127.0.0.1:1143`
- Container connects via: `host.docker.internal:1143`
- Configured in `docker-compose.yml` with `extra_hosts`
- Set `PROTON_IMAP_SERVER=host.docker.internal` in `.env`
- If Bridge uses STARTTLS mode, set `PROTON_USE_SSL=false`

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
      memory: 2G  # Increase from 1G
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

3. **Use container orchestration**: Consider Kubernetes or Docker Swarm for multi-host deployments

4. **Configure CI/CD**: Automate builds on code pushes using GitHub Actions or similar

## Image Metadata

The Docker image includes OCI labels:
- `org.opencontainers.image.title`: Email Security Pipeline
- `org.opencontainers.image.description`: Comprehensive email security analysis and threat detection
- `org.opencontainers.image.version`: 1.0

View with:
```bash
docker inspect email-security-pipeline:latest | jq '.[0].Config.Labels'
```
