## 2024-05-30 - Optimize IMAP SIZE Parsing
**Learning:** Parsing responses in tight loops (like checking `RFC822.SIZE` in fetch responses) using string slicing, `.find()`, and string splitting creates significant overhead from memory allocations and Python bytecode execution. A pre-compiled regular expression that directly extracts the target data is cleaner and more efficient.
**Action:** Identify and replace repeated custom string extraction logic with pre-compiled regex operations at the module level.
