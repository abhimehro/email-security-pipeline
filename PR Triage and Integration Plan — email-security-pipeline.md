# PR Triage and Integration Plan — email-security-pipeline

> **Last updated:** 2026-02-09
> **Previous batch (PRs #63–#95):** Merged/closed in earlier triage cycle.
> **Current batch (PRs #121–#152):** 24 open Jules-generated PRs reviewed below.

---

## 1. Problem Statement

The repository has accumulated 24 open Jules-generated PRs across three series:
* **Sentinel** (Security) — 8 PRs fixing vulnerabilities
* **Bolt** (Performance) — 7 PRs optimizing hot paths
* **Palette** (UX/CLI) — 8 PRs improving user experience

Several PRs touch the same files with different approaches, creating overlap and potential merge conflicts. This plan identifies which PRs to merge, which to close as superseded, and the recommended merge order.

---

## 2. PR Inventory

### 2.1 Security Track (Sentinel PRs)

| PR | Title | Files Changed | Severity | Recommendation |
|----|-------|--------------|----------|----------------|
| #123 | Fix DoS risks in logging and IMAP | `src/main.py`, `src/modules/email_ingestion.py`, `tests/test_security_fixes.py` | MEDIUM | ✅ **Merge** |
| #125 | Redact sensitive query params in webhook alerts | `src/modules/alert_system.py`, `tests/test_alert_leak_prevention.py`, `requirements.txt` | MEDIUM | ✅ **Merge** |
| #128 | Fix missing dangerous file extensions | `src/modules/media_analyzer.py`, `tests/test_media_analyzer_security.py` | HIGH | ✅ **Merge** |
| #134 | Fix sensitive webhook exposure in logs | `src/utils/config.py`, `tests/test_config_security.py` | HIGH | ✅ **Merge** |
| #137 | Prevent DoS in media analysis (frame resize + safe imports) | `src/modules/media_analyzer.py`, `tests/test_media_security.py`, `requirements.txt` | HIGH | ✅ **Merge** |
| #140 | Prevent sensitive data caching in NLP analyzer | `src/modules/nlp_analyzer.py`, `tests/test_nlp_cache_security.py` | MEDIUM | ✅ **Merge** |
| #143 | Fix Log Spoofing via BiDi Characters | `src/utils/sanitization.py`, `tests/test_sanitization_security.py` | HIGH | ✅ **Merge** |
| #146 | Fix archive bypass vulnerability (zip inspection) | `src/modules/media_analyzer.py`, `tests/test_media_zip_security.py` | HIGH | ✅ **Merge** |
| #149 | Fix DoS vulnerability in Deepfake Detection (timeout) | `src/modules/media_analyzer.py`, `tests/test_media_timeout.py` | HIGH | ✅ **Merge** |

### 2.2 Performance Track (Bolt PRs)

| PR | Title | Files Changed | Recommendation |
|----|-------|--------------|----------------|
| #126 | Optimize NLP analyzer text processing | `src/modules/nlp_analyzer.py` | ✅ **Merge** |
| #135 | Optimize logging sanitization with regex + early truncation | `src/utils/sanitization.py` | ⚠️ **Close** — Conflicts with #143 (BiDi fix). #143 is more important (security). |
| #138 | Optimize `_sanitize_filename` performance | `src/modules/email_ingestion.py` | ✅ **Merge** |
| #141 | Optimize deepfake detection loop (cv2 functions) | `src/modules/media_analyzer.py`, `requirements.txt` | ✅ **Merge** |
| #147 | Optimize SpamAnalyzer regex and URL extraction | `tests/benchmark_spam_analyzer.py`, `tests/benchmark_spam_regex.py` | ⚠️ **Close** — Only adds benchmark files, no production code changes. |
| #150 | Optimize `sanitize_for_logging` with `str.translate` | `src/utils/sanitization.py` | ⚠️ **Close** — Conflicts with #143 (BiDi fix). #143 replaces the same lines with category-based filtering. |
| #152 | Parallelize email analysis pipeline | `src/main.py` | ✅ **Merge** |

### 2.3 UX / CLI Track (Palette PRs)

| PR | Title | Files Changed | Recommendation |
|----|-------|--------------|----------------|
| #121 | Add clean report for low-risk emails | `src/modules/alert_system.py` | ✅ **Merge** |
| #124 | Improve configuration error reporting | `src/main.py`, `src/utils/config.py` | ✅ **Merge** |
| #136 | Add actionable error tips for auth failures | `src/modules/email_ingestion.py` | ✅ **Merge** |
| #139 | Add progress bar for email analysis | `src/main.py`, `src/utils/ui.py` | ⚠️ **Close** — Conflicts with #152 (parallel analysis) which changes the same loop. |
| #142 | Improve setup script UX with venv support | `setup.sh` | ✅ **Merge** |
| #145 | Add CLI loading spinner | `src/main.py`, `src/utils/ui.py` | ✅ **Merge** |
| #148 | Add summary table to connectivity check | `scripts/check_mail_connectivity.py` | ✅ **Merge** |
| #151 | Add CLI startup configuration summary | `src/main.py` | ✅ **Merge** |

---

## 3. Overlap and Conflict Analysis

### 3.1 `src/utils/sanitization.py` — 3-way conflict
* **PR #143** (Sentinel): Replaces `ord(ch) >= 32` filtering with `unicodedata.category` exclusion — **SECURITY FIX, must merge**
* **PR #135** (Bolt): Replaces the same line with compiled regex `CONTROL_CHARS_PATTERN` — **Conflicts with #143**
* **PR #150** (Bolt): Replaces the same line with `str.translate` — **Conflicts with #143**
* **Resolution:** Merge #143 first (security takes priority). Close #135 and #150 as superseded.

### 3.2 `src/modules/media_analyzer.py` — 4 PRs touch this file
* **PR #128**: Adds dangerous extensions — orthogonal, merge first
* **PR #137**: Adds frame resize + safe imports — orthogonal, merge after #128
* **PR #146**: Adds zip inspection — orthogonal, merge after #137
* **PR #149**: Adds deepfake timeout — orthogonal, merge after #146
* **PR #141** (Bolt): Optimizes deepfake loop — merge after #149
* **Resolution:** Merge in order: #128 → #137 → #146 → #149 → #141. May need minor conflict resolution.

### 3.3 `src/modules/nlp_analyzer.py` — 2 PRs touch this file
* **PR #126** (Bolt): Refactors `analyze()` method to iterate parts separately, adds `_scan_text_patterns()` and `_run_transformer_analysis()`
* **PR #140** (Sentinel): Replaces `lru_cache` with hash-based cache in `analyze_with_transformer()`
* **Resolution:** These are independent changes to different methods. Merge #140 first (security), then #126.

### 3.4 `src/main.py` — 6 PRs touch this file
* **PR #123**: Adds `RotatingFileHandler` — orthogonal to others
* **PR #124**: Adds `ConfigurationError` handling — orthogonal
* **PR #139**: Adds progress bar to analysis loop — **conflicts with #152**
* **PR #145**: Adds Spinner to init/fetch — orthogonal
* **PR #151**: Adds config summary method — orthogonal
* **PR #152**: Parallelizes `_analyze_email()` — changes same loop as #139
* **Resolution:** Merge #123 → #124 → #145 → #151 → #152. Close #139 (progress bar conflicts with parallelization).

### 3.5 `src/modules/email_ingestion.py` — 3 PRs touch this file
* **PR #123**: Adds IMAP timeout — small orthogonal change
* **PR #136**: Adds auth tips — orthogonal
* **PR #138**: Optimizes `_sanitize_filename` — orthogonal
* **Resolution:** No conflicts. Merge in any order.

---

## 4. Recommended Merge Order

### Phase 1: Security (Highest Priority)
Merge security fixes first to establish a safe baseline.

1. **PR #134** — Fix sensitive webhook exposure in logs (`config.py` repr)
2. **PR #143** — Fix Log Spoofing via BiDi Characters (`sanitization.py`)
3. **PR #123** — Fix DoS risks in logging and IMAP (`main.py`, `email_ingestion.py`)
4. **PR #128** — Fix missing dangerous file extensions (`media_analyzer.py`)
5. **PR #137** — Prevent DoS in media analysis (`media_analyzer.py`)
6. **PR #146** — Fix archive bypass vulnerability (`media_analyzer.py`)
7. **PR #149** — Fix DoS in Deepfake Detection (`media_analyzer.py`)
8. **PR #140** — Prevent sensitive data caching in NLP (`nlp_analyzer.py`)
9. **PR #125** — Redact sensitive query params in webhooks (`alert_system.py`)

### Phase 2: Performance
After security baseline is set, apply performance improvements.

1. **PR #138** — Optimize `_sanitize_filename` (`email_ingestion.py`)
2. **PR #126** — Optimize NLP analyzer text processing (`nlp_analyzer.py`)
3. **PR #141** — Optimize deepfake detection loop (`media_analyzer.py`)
4. **PR #152** — Parallelize email analysis pipeline (`main.py`)

### Phase 3: UX / CLI
Apply user experience improvements last.

1. **PR #121** — Add clean report for low-risk emails (`alert_system.py`)
2. **PR #124** — Improve configuration error reporting (`config.py`, `main.py`)
3. **PR #136** — Add actionable error tips for auth failures (`email_ingestion.py`)
4. **PR #145** — Add CLI loading spinner (`main.py`, `ui.py`)
5. **PR #148** — Add summary table to connectivity check (`check_mail_connectivity.py`)
6. **PR #151** — Add CLI startup configuration summary (`main.py`)
7. **PR #142** — Improve setup script UX with venv support (`setup.sh`)

### PRs to Close (Superseded/Conflicting)
1. **PR #135** — Close (superseded by #143; security BiDi fix takes priority over regex optimization)
2. **PR #150** — Close (superseded by #143; same lines modified differently)
3. **PR #139** — Close (conflicts with #152 parallelization; progress bar incompatible with parallel execution)
4. **PR #147** — Close (only adds benchmark files, no production code changes; benchmarks can be run independently)

---

## 5. Post-Merge Validation

After each phase:
* Run test suite: `python -m pytest tests/ --ignore=tests/test_media_analyzer_security.py --ignore=tests/test_media_magic.py --ignore=tests/test_deepfake_detection.py --ignore=tests/test_media_analyzer_leak.py --ignore=tests/test_alert_system_security.py`
* Manual checks:
    * Run `scripts/check_mail_connectivity.py` with providers enabled/disabled
    * Start main pipeline with test `.env` to verify banner and startup flow
    * Check logs for proper coloring (console) and plain format (file)

## 6. Post-Triage Cleanup

Once all preferred PRs are merged:
* Close all superseded PRs (#135, #139, #147, #150) with explanatory comments
* Delete associated branches after closing
* Update docs if behavior changed visibly:
    * `README.md`
    * `QUICK_REFERENCE.md`
    * `ENV_SETUP.md`

## 7. Branch Cleanup

After merging/closing, the following branches should be deleted:
* `bolt/optimize-sanitization-regex-12070237891610644074` (PR #135 — superseded)
* `bolt/optimize-sanitization-10956773793891408044` (PR #150 — superseded)
* `palette-progress-bar-11040315300213485710` (PR #139 — superseded)
* `bolt/spam-regex-optimization-4374342007678295719` (PR #147 — benchmarks only)
* All other branches after their PRs are merged
