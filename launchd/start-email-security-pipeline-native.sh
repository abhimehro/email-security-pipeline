#!/bin/zsh
# Start the email-security-pipeline natively (Python venv, no Docker/Colima).
#
# MIGRATION 2026-11-22: the pipeline moved from Docker-on-Colima to a native
# venv (.venv, Python 3.13) per VENV_MIGRATION_GUIDE.md. This frees the
# Colima VM (3 GB disk, 2 GB RAM on an 8 GB machine driving heavy swap).
# The previous Docker flow lives in start-email-security-pipeline.sh.docker
# (kept for rollback).
#
# SECURITY: Runs under launchd with a fixed PATH; does not load secrets itself
# — the pipeline loads .env via python-dotenv at startup.
set -euo pipefail

export HOME="${HOME:-/Users/speedybee}"
export PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:${HOME}/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin

PROJECT_DIR="${PROJECT_DIR:-${0:A:h:h}}"
PROJECT_DIR="${PROJECT_DIR:A}"
ENV_FILE="$PROJECT_DIR/.env"
VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"
LOG_TAG="email-security-pipeline"

log() {
	print -r -- "[$LOG_TAG] $*"
}

log_err() {
	print -r -- "[$LOG_TAG] $*" >&2
}

cd "$PROJECT_DIR"

# SECURITY & OPERATIONAL RELIABILITY: Fail fast if .env is a directory or
# missing (same guard as the Docker flow; python-dotenv would otherwise
# silently run with zero accounts configured).
if [[ -d $ENV_FILE ]]; then
	log_err "Configuration path $ENV_FILE is a directory, not a file."
	log_err "Remove the empty directory and create a valid .env file."
	exit 1
fi

if [[ ! -f $ENV_FILE ]]; then
	log_err "Configuration file $ENV_FILE not found."
	log_err "Copy .env.example to .env first."
	exit 1
fi

if [[ ! -x $VENV_PYTHON ]]; then
	log_err "Native venv python not found at $VENV_PYTHON"
	log_err "Recreate with: python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt"
	exit 1
fi

# Native host override: .env carries PROTON_IMAP_SERVER=host.docker.internal
# from the Docker era; natively Proton Mail Bridge listens on 127.0.0.1:1143.
# Environment variables take precedence over .env (src/utils/config.py), so
# this override requires no .env edit.
export PROTON_IMAP_SERVER=127.0.0.1

log "Starting email-security-pipeline natively (venv python: $VENV_PYTHON)"
exec "$VENV_PYTHON" src/main.py
