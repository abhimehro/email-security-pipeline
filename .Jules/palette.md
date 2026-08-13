## 2024-08-13 - [Fix Terminal UI Layout Shifts]
**Learning:** When building terminal UIs, replacing unformatted placeholder text (like `Waiting...`) with dynamically sized components mid-operation causes jarring horizontal layout shifts. Screen readers also benefit from immediately parsing the full UI structure.
**Action:** Always render the fully formatted initial state (including progress bars, zeroed timers, and colored symbols) in the static setup frame before beginning the dynamic refresh loop.
