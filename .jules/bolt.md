## 2025-03-05 - Remove unnecessary sleep in IMAP fetch batching
**Learning:** Hardcoded `time.sleep()` delays inside IO-bound batch processing loops create massive artificial bottlenecks, scaling linearly with batch counts, and can often be safely removed if upstream providers handle rate-limiting natively or the overhead naturally serves as throttling.
**Action:** When inspecting loops around I/O, question explicit `sleep` logic—benchmark it, ensure no server-side 429s are triggered on removal, and delete the artificial delays for massive throughput gains.
