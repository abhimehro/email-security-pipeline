# ABHI-1358/1359/1360/1361: Command injection via source in automation scripts

## Issue mapping
| Linear | Script | Primary repo | Status |
|--------|--------|--------------|--------|
| ABHI-1358 | close_prs.sh | personal-config | Duplicate tracker of ABHI-1360 |
| ABHI-1359 | fix_drafts.sh | personal-config | Covered by secure scripts/fix_drafts.sh |
| ABHI-1360 | close_prs.sh | email-security-pipeline | Covered by scripts/close_prs.sh |
| ABHI-1361 | fix_drafts.sh | personal-config | Duplicate tracker of ABHI-1359 |

## Plan
- [x] Confirm vulnerable `source` pattern and locate affected files
- [x] Add `scripts/gh_token_env.py` for safe env-file parsing (no shell execution)
- [x] Add secure `scripts/close_prs.sh` that loads GH_TOKEN via Python parser
- [x] Add shared `scripts/load_gh_token.sh` helper
- [x] Add secure `scripts/fix_drafts.sh` for ABHI-1359/1361
- [x] Add security tests for malicious env content and verify no `source`/`.` on env files
- [x] Run test suite
- [ ] Commit, push, and update PR

## Security notes
- Trust boundary: `GH_TOKEN.env` is local filesystem input — treat as untrusted
- Fail secure: reject malformed or suspicious env lines instead of executing them
- Never use `source` or `.` on external env files
- personal-config copies still need updating to call `../email-security-pipeline/scripts/gh_token_env.py`
