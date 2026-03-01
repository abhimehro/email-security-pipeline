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
