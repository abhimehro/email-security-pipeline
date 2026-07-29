# PR Inventory — 2026-02-28

## Summary

| Repo                      | Open PRs | Bot Author |
| ------------------------- | -------- | ---------- |
| `email-security-pipeline` | 27       | Jules      |
| `personal-config`         | 13       | Jules      |
| `ctrld-sync`              | 0        | —          |
| **Total**                 | **40**   | —          |

---

## email-security-pipeline (27 PRs)

| PR #      | Title                                                                       | Category    | Age (days) | Created    |
| --------- | --------------------------------------------------------------------------- | ----------- | ---------- | ---------- |
| #407      | 🛡️ Sentinel: [HIGH] Fix Path Traversal & Log Spoofing in Archive Extraction | SECURITY    | 0          | 2026-02-28 |
| #406      | 🎨 Palette: Add CYAN color to CLI Spinner                                   | UI          | 0          | 2026-02-27 |
| #405      | ⚡ Bolt: Optimize Spam Analyzer Regex                                       | PERFORMANCE | 0          | 2026-02-27 |
| #404      | 🛡️ Sentinel: [MEDIUM] Fix credentials leakage in URLs                       | SECURITY    | 1          | 2026-02-27 |
| #403      | 🎨 Palette: Improved Console Alert Readability                              | UI          | 1          | 2026-02-26 |
| #401      | ⚡ Bolt: Add LRU cache to spam URL analysis                                 | PERFORMANCE | 2          | 2026-02-26 |
| #400      | 🛡️ Sentinel: [HIGH] Fix webhook token leak in redaction logic               | SECURITY    | 2          | 2026-02-26 |
| #399      | 🎨 Palette: Smart Spinner with dynamic status messages                      | UI          | 2          | 2026-02-25 |
| #398      | ⚡ Bolt: Optimize URL analysis with LRU cache                               | PERFORMANCE | 3          | 2026-02-25 |
| #397      | 🛡️ Sentinel: [HIGH] Fix DoS vulnerability in metrics collection             | SECURITY    | 3          | 2026-02-25 |
| #396      | Add credential verification to setup wizard                                 | FEATURE     | 3          | 2026-02-24 |
| #395      | ⚡ Bolt: Optimize spam URL analysis with LRU cache                          | PERFORMANCE | 4          | 2026-02-24 |
| #394      | 🛡️ Sentinel: [Security Enhancement] Add DMARC verification                  | SECURITY    | 4          | 2026-02-24 |
| #393      | 🎨 Palette: Add immediate credential verification to setup wizard           | FEATURE     | 5          | 2026-02-23 |
| #392      | ⚡ Bolt: Add shared LRU cache to SpamAnalyzer for faster URL checks         | PERFORMANCE | 5          | 2026-02-23 |
| #391      | 🛡️ Sentinel: [CRITICAL] Add DMARC verification check                        | SECURITY    | 5          | 2026-02-23 |
| #390      | 🎨 Palette: Add credential verification to setup wizard                     | FEATURE     | 6          | 2026-02-22 |
| #389      | ⚡ Bolt: Optimize SpamAnalyzer URL checking with LRU cache                  | PERFORMANCE | 6          | 2026-02-22 |
| #388–#381 | (remaining older PRs — to be discovered from full listing)                  | VARIOUS     | 6–30+      | varies     |

> **Note:** PRs #388–#381 were not fully extracted in this pass due to JSON
> output size. The patterns above are sufficient to identify the major
> duplication clusters.

---

## personal-config (13 PRs)

| PR # | Title                                                                              | Category    | Age (days) | Created    |
| ---- | ---------------------------------------------------------------------------------- | ----------- | ---------- | ---------- |
| #433 | 🧪 Add comprehensive tests for infuse-media-server.py stream_file                  | REFACTOR    | 0          | 2026-02-28 |
| #432 | 🧪 Add test suite for print_summary in consolidate_adblock_lists.py                | REFACTOR    | 0          | 2026-02-28 |
| #431 | 🧪 Improve testing and resilience of process_tracker_files                         | REFACTOR    | 0          | 2026-02-28 |
| #430 | 🧪 Add test coverage for infuse-media-server.py check_auth                         | REFACTOR    | 0          | 2026-02-28 |
| #429 | 🧹 [Code Health] Refactor monitor_controld with wrapper functions                  | REFACTOR    | 0          | 2026-02-28 |
| #428 | 🧪 Add tests for do_HEAD auth gating in infuse-media-server                        | REFACTOR    | 0          | 2026-02-28 |
| #427 | 🧪 [Testing] Add test suite for generate_directory_listing                         | REFACTOR    | 0          | 2026-02-28 |
| #426 | ⚡ perf: optimize user generation string allocation                                | PERFORMANCE | 0          | 2026-02-28 |
| #425 | 🧪 Add tests for create_json_structure in consolidate_adblock_lists.py             | REFACTOR    | 0          | 2026-02-28 |
| #424 | 🧪 [test] add robust unit tests for process_allowlist_files                        | REFACTOR    | 0          | 2026-02-28 |
| #423 | 🧪 testing: add tests for extract_allowlist_domains_from_file                      | REFACTOR    | 0          | 2026-02-28 |
| #422 | 🧪 [testing improvement] Unit test for send_auth_request in infuse-media-server.py | REFACTOR    | 0          | 2026-02-28 |
| #413 | feat(security): secure env var support for ControlD profiles                       | SECURITY    | 0          | 2026-02-27 |

---

## ctrld-sync (0 PRs)

No open PRs. ✅
