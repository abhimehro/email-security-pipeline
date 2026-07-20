## 2025-03-05 - Remove unnecessary sleep in IMAP fetch batching
**Learning:** Hardcoded `time.sleep()` delays inside IO-bound batch processing loops create massive artificial bottlenecks, scaling linearly with batch counts, and can often be safely removed if upstream providers handle rate-limiting natively or the overhead naturally serves as throttling.
**Action:** When inspecting loops around I/O, question explicit `sleep` logic—benchmark it, ensure no server-side 429s are triggered on removal, and delete the artificial delays for massive throughput gains.
## 2025-05-19 - Join text lists before string search
**Learning:** Calling `.count()` or `.findall()` on strings in a loop incurs significant Python overhead compared to doing it on one joined string. Join lists of valid string parts, then do search, when finding aggregate counts.
**Action:** When finding string matches across an array of text sections, join them into a single block with newline and perform string match or regex findall, especially when the operation length scales with array items.
