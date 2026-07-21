## 2025-03-05 - Remove unnecessary sleep in IMAP fetch batching
**Learning:** Hardcoded `time.sleep()` delays inside IO-bound batch processing loops create massive artificial bottlenecks, scaling linearly with batch counts, and can often be safely removed if upstream providers handle rate-limiting natively or the overhead naturally serves as throttling.
**Action:** When inspecting loops around I/O, question explicit `sleep` logic—benchmark it, ensure no server-side 429s are triggered on removal, and delete the artificial delays for massive throughput gains.
## 2024-05-15 - Fast Sequential Filtering
**Learning:** When evaluating items with a function that both parses and validates, standard explicit iteration with early continues is surprisingly fast in CPython. However, using a list comprehension powered by an inner generator expression (e.g., `[p for p in (func(x) for x in data) if p]`) reduces pure loop overhead and provides an ~15-20% speedup for simple batch processing without sacrificing readability or requiring the walrus operator.
**Action:** Default to list comprehensions over nested iteration when mapping + filtering a sequence without heavy internal side effects.
