#!/usr/bin/env bash
# SECURITY: This helper must be executed, not sourced.
# It prints a resolved GH_TOKEN to stdout and exits 0, or prints an error to
# stderr and exits 1. Callers should capture it with:
# GH_TOKEN="$(bash "${SCRIPT_DIR}/load_gh_token.sh")"

# Guard must run before set -e so a sourced return 1 does not kill the caller.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
	echo "error: load_gh_token.sh must be executed, not sourced." >&2
	# shellcheck disable=SC2016
	printf ' use: GH_TOKEN="$(bash %q)"\n' "${BASH_SOURCE[0]}" >&2
	# shellcheck disable=SC2317
	return 1 2>/dev/null || exit 1
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HELPER="${SCRIPT_DIR}/gh_token_env.py"
DEFAULT_ENV_FILE="${REPO_ROOT}/GH_TOKEN.env"
ENV_FILE="${GH_TOKEN_ENV_FILE:-${DEFAULT_ENV_FILE}}"

if [[ -n ${GH_TOKEN-} ]]; then
	printf '%s\n' "${GH_TOKEN}"
	exit 0
fi

if command -v gh >/dev/null 2>&1 && gh auth status -h github.com >/dev/null 2>&1; then
	token="$(gh auth token 2>/dev/null || true)"
	token="${token//[[:space:]]/}"
	if [[ -n ${token} ]]; then
		printf '%s\n' "${token}"
		exit 0
	fi
fi

if [[ -f ${ENV_FILE} ]]; then
	if token="$(python3 "${HELPER}" --get GH_TOKEN "${ENV_FILE}")"; then
		if [[ -n ${token} ]]; then
			printf '%s\n' "${token}"
			exit 0
		fi
	fi
fi

echo "error: GH_TOKEN is not configured." >&2
echo "Export GH_TOKEN, run 'gh auth login', or create a GH_TOKEN.env file." >&2
exit 1
