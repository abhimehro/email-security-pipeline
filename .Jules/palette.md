## 2026-08-26 - [Terminal Truncation Shift]
**Learning:** When measuring string lengths for terminal UI truncation, naive length calculations include ANSI escape sequences (colors, cursors) which leads to premature wrapping. Stripping them before calculating width ensures accurate constraints.
**Action:** Always strip ANSI characters via regex before measuring length when dealing with terminal UX formatting.
