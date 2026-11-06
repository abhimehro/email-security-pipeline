#!/bin/zsh
# Start Colima (if needed) and bring up the email-security-pipeline compose stack.
# SECURITY: Runs under launchd with a fixed PATH; does not load secrets itself —
# docker compose mounts .env into the container.
set -euo pipefail

export HOME="${HOME:-/Users/speedybee}"
export PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:${HOME}/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin

PROJECT_DIR="${PROJECT_DIR:-${0:A:h:h}}"
COMPOSE_FILE="${COMPOSE_FILE:-$PROJECT_DIR/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-$PROJECT_DIR/.env}"
DOCKER_CONTEXT="colima"
# Colima cold-start on Apple Virtualization can exceed 3 minutes after a crash.
READY_ATTEMPTS=150 # 150 * 2s = 300s
LOG_TAG="email-security-pipeline"

log() {
	print -r -- "[$LOG_TAG] $*"
}

log_err() {
	print -r -- "[$LOG_TAG] $*" >&2
}

# Resolve CLI paths without hard-failing on a single Homebrew layout.
resolve_bin() {
	local name="$1"
	local candidate
	for candidate in \
		"/opt/homebrew/bin/${name}" \
		"/usr/local/bin/${name}" \
		"${HOME}/.local/bin/${name}" \
		"${HOME}/bin/${name}"; do
		if [[ -x $candidate ]]; then
			print -r -- "$candidate"
			return 0
		fi
	done
	if command -v "$name" >/dev/null 2>&1; then
		command -v "$name"
		return 0
	fi
	return 1
}

cd "$PROJECT_DIR"

# SECURITY & OPERATIONAL RELIABILITY: Fail fast if .env is a directory or missing.
# Docker bind-mounting ./.env:/app/.env:ro when .env is missing auto-creates .env/ as a directory,
# breaking docker compose and python-dotenv. Checking upfront prevents this corruption state.
if [[ -d $ENV_FILE ]]; then
	log_err "Configuration path $ENV_FILE is a directory, not a file (often auto-created by Docker when bind-mounting a missing .env)."
	log_err "Remove the empty directory and create a valid .env file."
	exit 1
fi

if [[ ! -f $ENV_FILE ]]; then
	log_err "Configuration file $ENV_FILE not found."
	log_err "Refusing to start compose so Docker does not create an empty .env/ directory. Copy .env.example to .env first."
	exit 1
fi

DOCKER_BIN="$(resolve_bin docker)" || {
	log_err "docker CLI not found on PATH ($PATH)"
	log_err "Install with: brew install docker docker-compose"
	exit 1
}

COLIMA_BIN=""
if COLIMA_BIN="$(resolve_bin colima)"; then
	:
else
	COLIMA_BIN=""
fi

log "Using docker=$DOCKER_BIN colima=${COLIMA_BIN:-<missing>}"

# Ensure Colima is up. Do not swallow failures — silent `|| true` left launchd
# retrying forever while docker never became ready.
if [[ -n $COLIMA_BIN ]]; then
	if ! "$COLIMA_BIN" status >/dev/null 2>&1; then
		log "Colima not running; starting (shared VM — also used by other services)..."
		# Prefer restarting the existing default profile; do not recreate the VM.
		if ! "$COLIMA_BIN" start 2>&1; then
			log_err "colima start failed; attempting colima stop then start..."
			"$COLIMA_BIN" stop >/dev/null 2>&1 || true
			if ! "$COLIMA_BIN" start 2>&1; then
				log_err "colima start failed after stop/start. Check ~/.colima/_lima/colima/ha.stderr.log"
				exit 1
			fi
		fi
	else
		log "Colima already running"
	fi
else
	# Fail fast: waiting 300s without a way to start the VM is wasted KeepAlive churn.
	log_err "colima binary not found (checked /opt/homebrew/bin, /usr/local/bin, ~/.local/bin, PATH)"
	log_err "Install/restore with: brew install colima && colima start"
	log_err "Do NOT colima delete — existing profile data lives under ~/.colima"
	exit 1
fi

for i in {1..$READY_ATTEMPTS}; do
	if "$DOCKER_BIN" --context "$DOCKER_CONTEXT" info >/dev/null 2>&1; then
		log "Docker context '$DOCKER_CONTEXT' ready (attempt $i); starting compose..."
		exec "$DOCKER_BIN" --context "$DOCKER_CONTEXT" compose -f "$COMPOSE_FILE" up -d --remove-orphans
	fi
	# Surface progress every ~30s so launchd stderr is actionable.
	if ((i % 15 == 0)); then
		log_err "Waiting for Docker context '$DOCKER_CONTEXT' (attempt $i/$READY_ATTEMPTS)..."
		"$COLIMA_BIN" status 2>&1 | while IFS= read -r line; do
			log_err "colima status: $line"
		done || true
	fi
	sleep 2
done

log_err "Colima/Docker did not become ready within $((READY_ATTEMPTS * 2)) seconds"
log_err "Hint: colima status; docker --context colima info; tail ~/.colima/_lima/colima/ha.stderr.log"
exit 1
