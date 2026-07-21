## 2025-03-05 - Remove unnecessary sleep in IMAP fetch batching
**Learning:** Hardcoded `time.sleep()` delays inside IO-bound batch processing loops create massive artificial bottlenecks, scaling linearly with batch counts, and can often be safely removed if upstream providers handle rate-limiting natively or the overhead naturally serves as throttling.
**Action:** When inspecting loops around I/O, question explicit `sleep` logic—benchmark it, ensure no server-side 429s are triggered on removal, and delete the artificial delays for massive throughput gains.

## 2026-07-21 - Optimize list append loop using extend and list comp
**Learning:** In CPython, appending items from an iterator to a list conditionally inside a `for` loop carries a significant performance overhead due to the interpreter constantly stepping through the bytecode for the loop and the `.append()` method resolution.
**Action:** Replace `for item in iter: if item: lst.append(item)` with `lst.extend([item for item in iter if item])`. The memory overhead of building a temporary list in the comprehension is almost always outweighed by the speed gained from pushing the list generation and extension down into C code, leading to a ~26% performance improvement.
