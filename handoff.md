# ELIR Handoff

**Purpose:**
Added a test `test_gate_uses_search_not_match` inside `TestScanTextPatternsTwoPhase` in `tests/test_nlp_scan_text_patterns.py` to prevent regression bugs related to regex match vs search.

**Security:**
Guards against a "silent failure" threat scenario where the `simple_master_pattern` gate uses `.match()` instead of `.search()`, which would skip pattern detection if threats appear mid-string instead of exactly at the beginning.

**Failure Modes:**
If the gate mistakenly changes to `.match()`, this test will immediately fail, signaling the regression before deployment.

**Review Checklist:**
*   Verify the test strings start with neutral words before the keyword (e.g. `However, verify your account right now!`).
*   Verify `assertGreater` targets the correct key in the `matches` dictionary to assert detection.

**Maintenance:**
If new keywords are added or patterns are restructured, make sure this `test_gate_uses_search_not_match` explicitly tests an active pattern. Currently, it tests for `verify your account` (`SE` pattern).
