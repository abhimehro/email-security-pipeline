#!/usr/bin/env bash
# Mark draft PRs ready and merge them using a safely loaded GH_TOKEN.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=load_gh_token.sh
source "${SCRIPT_DIR}/load_gh_token.sh"

usage() {
  cat <<'EOF'
Usage: fix_drafts.sh REPO PR_NUMBER [REPO PR_NUMBER ...]

Safely loads GH_TOKEN from an env file without using source/. and marks each
draft PR ready before merging it with --squash --delete-branch.
EOF
}

if [[ $# -lt 2 || $(( $# % 2 )) -ne 0 ]]; then
  echo "error: expected REPO PR_NUMBER pairs" >&2
  usage >&2
  exit 2
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

load_gh_token "${SCRIPT_DIR}"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI is required but not installed" >&2
  exit 1
fi

fix_and_merge() {
  local repo="$1"
  local pr_number="$2"

  if ! [[ "${pr_number}" =~ ^[0-9]+$ ]]; then
    echo "error: invalid PR number for ${repo}: ${pr_number}" >&2
    exit 2
  fi

  echo "Marking ${repo}#${pr_number} ready and merging..."
  gh pr ready "${pr_number}" --repo "${repo}"
  gh pr merge "${pr_number}" --repo "${repo}" --squash --delete-branch
}

while [[ $# -gt 0 ]]; do
  fix_and_merge "$1" "$2"
  shift 2
done
