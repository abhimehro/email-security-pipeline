# Local Development Environment Setup

## Quick Start

### Option 1: Local Python venv - Recommended for fast iteration

```bash
# Create and activate venv
python3.13 -m venv .venv
source .venv/bin/activate

# Install runtime + dev dependencies
python3.13 -m pip install -r requirements-dev.txt

# Run tests
python3 -m pytest
```

### Option 2: Docker - Canonical for reproducibility

```bash
# Verify Docker is running - see Troubleshooting below
docker build -t email-security-pipeline:latest .
```

The runtime image installs `requirements.txt` only (no pytest). Run tests on
the host:

```bash
python3 -m pip install -r requirements-ci.txt
python3 -m pytest
```

---

## Dependency Files Explained

All requirements*.txt files use exact version pins to match CI green state (2026-09-13).

| File | Purpose | Use Case |
|------|---------|----------|
| requirements.txt | Runtime only | Production, base venv, Docker build |
| requirements-dev.txt | Runtime + local dev testing | Local dev loop with pytest, coverage |
| requirements-ci.txt | Runtime + CI tools | GitHub Actions, pre-commit hooks |

Note: -dev.txt and -ci.txt reference requirements.txt via "-r requirements.txt", ensuring a single source of truth.

---

## Troubleshooting

### Docker socket error: connect no such file or directory

The Colima VM socket becomes stale when:
- MacBook restarts
- Colima VM disk fills up or crashes
- Storage cleanup deletes the .colima/ directory

Recovery:

```bash
# Do not `colima delete` — that wipes the VM and is shared with Jellyfin /
# Control D host DNS (see AGENTS.md). Start the existing profile without
# resource overrides so an existing disk is never accidentally shrunk.
# If .colima/ was removed, verify/restore the shared DNS override first:
# (required after that cleanup; see personal-config/AGENTS.md)
~/dev/personal-config/scripts/free-port53-for-controld.sh --patch-colima-ignore
colima start || { colima stop; colima start; }

# Verify Docker is ready
docker ps
```

Run the `--patch-colima-ignore` command whenever `.colima/` was removed.
Configure any required CPU, memory, or disk growth separately through the
existing Colima profile configuration; do not add a smaller `--disk` override
to this recovery command.

### Docker build fails with dependency errors

1. Verify requirements.txt is populated (not empty):
   cat requirements.txt
   Should show: requests==2.34.2, numpy==2.5.2, etc.

2. Verify Dockerfile references the right file:
   grep "requirements" Dockerfile | head -5
   Should show: COPY requirements.txt .

3. Clean Docker cache and rebuild:
   docker system prune -a
   docker build -t email-security-pipeline:latest .

### Local venv install fails

```bash
# Ensure Python 3.13 is available
python3.13 --version

# If not, use Homebrew
brew install python@3.13

# Recreate venv
python3.13 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
```

---

## Version Pinning Strategy

All requirements*.txt use exact version pins: requests==2.34.2, not requests>=2.30

Why? Versions match CI green state as of 2026-09-13.

Benefits:
- Local dev matches CI behavior exactly
- Fresh clones dont silently upgrade major versions
- Dependency drift is explicit (requires deliberate bump + re-test)

To update a dependency:
1. Edit requirements.txt with new version
2. Test locally: python3 -m pip install -r requirements-ci.txt && python3 -m pytest
3. Verify Docker: docker build -t email-security-pipeline:test .
4. Commit: docs: bump requests to 2.35.0 for CVE fix
