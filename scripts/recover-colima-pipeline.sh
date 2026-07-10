#!/bin/zsh
# Recover shared Colima + email-security-pipeline after VM crash / launchd timeout.
# SAFE for shared Colima (Jellyfin / Stream 3): starts existing default profile only;
# does not delete the VM or wipe volumes.
#
# Usage:
#   ./scripts/recover-colima-pipeline.sh
#   ./scripts/recover-colima-pipeline.sh --rebuild   # rebuild image (needed after src/ changes)
#   ./scripts/recover-colima-pipeline.sh --test-alert # POST a synthetic ntfy payload (no IMAP)
set -euo pipefail

export PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/Users/speedybee/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin
REPO="${0:A:h:h}"
cd "$REPO"

REBUILD=0
TEST_ALERT=0
for arg in "$@"; do
	case "$arg" in
		--rebuild) REBUILD=1 ;;
		--test-alert) TEST_ALERT=1 ;;
		-h|--help)
			sed -n '1,20p' "$0"
			exit 0
			;;
	esac
done

resolve_bin() {
	local name="$1"
	local candidate
	for candidate in \
		"/opt/homebrew/bin/${name}" \
		"/usr/local/bin/${name}" \
		"${HOME}/.local/bin/${name}" \
		"${HOME}/bin/${name}"; do
		if [[ -x "$candidate" ]]; then
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

DOCKER_BIN="$(resolve_bin docker)" || {
	print -r -- "ERROR: docker CLI not found. brew install docker docker-compose" >&2
	exit 1
}
COLIMA_BIN="$(resolve_bin colima)" || {
	print -r -- "ERROR: colima binary not found at /opt/homebrew/bin/colima (or PATH)." >&2
	print -r -- "Restore with: brew install colima" >&2
	print -r -- "Then: colima start   # existing profile under ~/.colima — do NOT colima delete" >&2
	exit 1
}

print -r -- "==> Using docker=$DOCKER_BIN"
print -r -- "==> Using colima=$COLIMA_BIN"

print -r -- "==> Colima status"
if ! "$COLIMA_BIN" status; then
	print -r -- "==> Starting existing Colima profile (no recreate)..."
	"$COLIMA_BIN" start || {
		print -r -- "==> colima start failed; stop then start..."
		"$COLIMA_BIN" stop || true
		"$COLIMA_BIN" start
	}
fi

print -r -- "==> Waiting for docker --context colima..."
for i in {1..90}; do
	if "$DOCKER_BIN" --context colima info >/dev/null 2>&1; then
		print -r -- "Docker ready (attempt $i)"
		break
	fi
	sleep 2
	if (( i == 90 )); then
		print -r -- "ERROR: Docker context colima not ready" >&2
		exit 1
	fi
done

if (( REBUILD )); then
	print -r -- "==> Rebuilding image (src/ is not bind-mounted in production compose)..."
	"$DOCKER_BIN" --context colima compose -f "$REPO/docker-compose.yml" build
fi

print -r -- "==> Bringing up compose stack..."
"$DOCKER_BIN" --context colima compose -f "$REPO/docker-compose.yml" up -d --remove-orphans
"$DOCKER_BIN" --context colima compose -f "$REPO/docker-compose.yml" ps

print -r -- "==> Kickstarting LaunchAgent..."
launchctl kickstart -k "gui/$(id -u)/com.abhimehrotra.email-security-pipeline" || true

print -r -- "==> Recent container logs"
"$DOCKER_BIN" --context colima compose -f "$REPO/docker-compose.yml" logs --tail=40

if (( TEST_ALERT )); then
	# Non-secret: topic is already in .env as public ntfy channel name.
	# Does not touch IMAP credentials. Confirms host→ntfy path only.
	print -r -- "==> Sending synthetic ntfy test (host path; not via container)..."
	curl -fsS -H "Title: Email Security Pipeline test" \
		-H "Priority: default" \
		-H "Tags: test,email-security" \
		-d "Stream 2 recovery test at $(date -u +%Y-%m-%dT%H:%M:%SZ). If you see this, ntfy delivery works." \
		"https://ntfy.sh/email-security-pipeline"
	print -r -- ""
	print -r -- "Check your ntfy subscriber for topic email-security-pipeline."
fi

print -r -- "==> Done. App log: tail -f $REPO/logs/email_security.log"
print -r -- "    LaunchAgent err: tail -f ~/Library/Logs/email-security-pipeline/pipeline.err"
