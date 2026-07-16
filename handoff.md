══════════ ELIR ══════════
PURPOSE: Added test cases for `calculate_max_email_size` to cover edge conditions (negative and very large attachment limits).
SECURITY: Ensures the fallback default logic works for negative limits, and verifies overhead is still applied correctly to extreme inputs without crashing.
FAILS IF: The implementation of `calculate_max_email_size` is altered to not use `DEFAULT_MAX_EMAIL_SIZE` for negative numbers, or if it stops handling massive limits.
VERIFY: The tests passed and added coverage. Check CI to ensure regressions aren't introduced.
MAINTAIN: Keep the test cases aligned with the implementation variables `DEFAULT_MAX_EMAIL_SIZE` and `_OVERHEAD_BYTES`.
