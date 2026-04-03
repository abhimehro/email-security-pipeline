#!/bin/zsh
set -euo pipefail

export HOME=/Users/speedybee
export PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

COMPOSE_FILE="$HOME/dev/email-security-pipeline/docker-compose.yml"
PROJECT_DIR="$HOME/dev/email-security-pipeline"
DOCKER_BIN="/opt/homebrew/bin/docker"
COLIMA_BIN="/opt/homebrew/bin/colima"
DOCKER_CONTEXT="colima"

cd "$PROJECT_DIR"

if command -v "$COLIMA_BIN" >/dev/null 2>&1; then
	"$COLIMA_BIN" start >/dev/null 2>&1 || true
fi

for i in {1..90}; do
	if "$DOCKER_BIN" --context "$DOCKER_CONTEXT" info >/dev/null 2>&1; then
		exec "$DOCKER_BIN" --context "$DOCKER_CONTEXT" compose -f "$COMPOSE_FILE" up -d --remove-orphans
	fi
	sleep 2
done

echo "Colima/Docker did not become ready within 180 seconds" >&2
exit 1
