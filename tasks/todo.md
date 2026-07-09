# PR Review & Consolidation — Task Tracker

## Phase 1: Inventory & Triage
- [x] Discover all open PRs across 3 repos
- [x] Classify PRs by category
- [x] Detect duplicates and overlaps
- [/] Write inventory (`tasks/pr-inventory.md`)
- [/] Write triage report (`tasks/pr-triage.md`)
- [/] Write implementation plan for user review

## Phase 2: Review & Execute (email-security-pipeline)
- [ ] Close duplicate/superseded PERFORMANCE PRs (LRU cache cluster)
- [ ] Close duplicate/superseded FEATURE PRs (credential verification cluster)
- [ ] Close duplicate SECURITY PRs (DMARC check cluster)
- [ ] Close duplicate SECURITY PRs (webhook/URL redaction cluster)
- [ ] Review surviving SECURITY PRs (Gate 1–4)
- [ ] Review surviving PERFORMANCE PRs (Gate 1–4)
- [ ] Review surviving UI PRs (Gate 1–4)
- [ ] Review surviving FEATURE PRs (Gate 1–4)
- [ ] Merge approved PRs in priority order

## Phase 3: Report & Lessons
- [ ] Write session report (`tasks/pr-review-2026-02-28.md`)
- [ ] Update `tasks/lessons.md`

## Phase 4: MediaAnalyzer Refactor (Current Task)
- [x] Analyze `_check_content_type_mismatch` in `src/modules/media_analyzer.py`
- [x] Split logic into `_validate_signature_match` and `_validate_missing_signature` helper methods
- [x] Validate refactored logic with existing tests suite `PYTHONPATH=. pytest tests/`
- [x] Commit with ELIR summary message

## Phase 5: Development Environment Setup (Current Task)
- [x] Install lightweight development dependencies from `requirements-ci.txt`
- [x] Run `python3 -m pytest` to verify the local test environment
- [x] Run `python3 src/main.py` to demonstrate application startup behavior
- [x] Configure Cursor Cloud startup dependency refresh for future sessions

## Stream 2 Repair — Diagnosis (2026-07-09)

### Execution plan
- [x] Inspect LaunchAgent plist + `pipeline.err` / `pipeline.out`
- [x] Inspect Colima lima logs + docker.sock presence + app `logs/email_security.log`
- [x] Identify root causes (Colima down + alert gating mismatch)
- [x] Harden `launchd/start-email-security-pipeline.sh` (stop swallowing `colima start` errors; longer wait; progress logs)
- [x] Fix alert gating so medium/high layer risk notifies even when sum score < `THREAT_LOW`
- [x] Fix `shutdown.sh` to use `--context colima`
- [x] Add `scripts/recover-colima-pipeline.sh` for shared-Colima-safe recovery + optional rebuild/test-alert
- [x] File verification (2026-07-09): recovery **FAILED** — `/opt/homebrew/bin/colima` missing; LaunchAgent waited 300s then retried; app log still ends 2026-06-05; no docker.sock
- [x] Harden start/recover scripts: resolve bins via candidates; **fail fast** if colima missing (no 300s wait)
- [x] Colima CLI restored (brew); VM started without delete
- [x] `./scripts/recover-colima-pipeline.sh --rebuild --test-alert` — image rebuilt with alert gating fix; ntfy OK
- [x] Container healthy; IMAP cycle processed mail; webhooks firing (incl. score<30 medium/high)
- [x] In-container synthetic: low/5 skipped; high/18 dispatched to ntfy
- [x] Host ntfy confirmation: title `Stream2 E2E OK` (2026-07-09T18:49:15Z)

### Root causes (file evidence)
1. **Colima VM dead since 2026-06-04 19:55** — `ha.stderr.log`: `VirtualMachineStateError` → SIGTERM → `vz: CanRequestStop is not supported`. No `~/.colima/**/docker.sock`. App log last cycle ~2026-06-05 00:53.
2. **Start script hid failures** — `colima start >/dev/null 2>&1 || true` then 180s wait → launchd stderr spam `Colima/Docker did not become ready within 180 seconds`; KeepAlive retries forever.
3. **Alert gating mismatch** — `send_alert` required `overall_threat_score >= THREAT_LOW` (30) while `risk_level` can be `high` from spam layer at score ≥10 (`SPAM_THRESHOLD*2`). Example: 2026-06-04 `risk=high` score=18.00 with **no** webhook line.

### Colima note (shared with Stream 3 / Jellyfin)
- Do **not** `colima delete` / recreate disk. Prefer `colima start` on existing default profile.
- Recovery script only starts existing profile + compose up.
