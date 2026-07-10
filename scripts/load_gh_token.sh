#!/usr/bin/env bash
# SECURITY: Shared helper for loading GH_TOKEN without sourcing external env files.
# CAUTION: Only source this trusted helper — never source GH_TOKEN.env directly.

load_gh_token() {
  local script_dir="${1:?script directory is required}"
  local repo_root
  repo_root="$(cd "${script_dir}/.." && pwd)"

  local helper="${script_dir}/gh_token_env.py"
  local default_env_file="${repo_root}/GH_TOKEN.env"
  local env_file="${GH_TOKEN_ENV_FILE:-${default_env_file}}"

  if [[ -n "${GH_TOKEN:-}" ]]; then
    return 0
  fi

  if [[ ! -f "${env_file}" ]]; then
    echo "error: GH_TOKEN is unset and env file not found: ${env_file}" >&2
    return 1
  fi

  GH_TOKEN="$(python3 "${helper}" --get GH_TOKEN "${env_file}")"
  export GH_TOKEN
}
