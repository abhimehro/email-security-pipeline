#!/usr/bin/env bash
# Close one or more GitHub pull requests using a safely loaded GH_TOKEN.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=load_gh_token.sh
source "${SCRIPT_DIR}/load_gh_token.sh"
REPO="${GITHUB_REPOSITORY:-}"

usage() {
  cat <<'EOF'
Usage: close_prs.sh [--repo OWNER/NAME] [--comment TEXT] PR_NUMBER [PR_NUMBER...]

Safely loads GH_TOKEN from an env file without using source/. and closes PRs via gh.
EOF
}

COMMENT="Closed via close_prs.sh automation."

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --comment)
      COMMENT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 1 ]]; then
  echo "error: at least one PR number is required" >&2
  usage >&2
  exit 2
fi

load_gh_token "${SCRIPT_DIR}"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI is required but not installed" >&2
  exit 1
fi

gh_args=(pr close)
if [[ -n "${REPO}" ]]; then
  gh_args+=(--repo "${REPO}")
fi
gh_args+=(--comment "${COMMENT}")

for pr_number in "$@"; do
  if ! [[ "${pr_number}" =~ ^[0-9]+$ ]]; then
    echo "error: invalid PR number: ${pr_number}" >&2
    exit 2
  fi
  echo "Closing PR #${pr_number}..."
  gh "${gh_args[@]}" "${pr_number}"
done
