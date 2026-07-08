# ABHI-1360: Command Injection via source in close_prs.sh

## Plan
- [x] Confirm vulnerable `source` pattern and locate affected files
- [x] Add `scripts/gh_token_env.py` for safe env-file parsing (no shell execution)
- [x] Add secure `scripts/close_prs.sh` that loads GH_TOKEN via Python parser
- [x] Add security tests for malicious env content and verify no `source`/`.` usage
- [x] Run test suite and shellcheck
- [x] Commit, push, and open PR

## Security notes
- Trust boundary: `GH_TOKEN.env` is local filesystem input — treat as untrusted
- Fail secure: reject malformed or suspicious env lines instead of executing them
- Never use `source` or `.` on external env files
