## 2026-08-26 - [Terminal Truncation Shift]
**Learning:** When measuring string lengths for terminal UI truncation, naive length calculations include ANSI escape sequences (colors, cursors) which leads to premature wrapping. Stripping them before calculating width ensures accurate constraints.
**Action:** Always strip ANSI characters via regex before measuring length when dealing with terminal UX formatting.
## 2026-08-28 - [CLI Visual Hierarchy]
**Learning:** Standalone scripts often lack the visual polish of the core application. Unwrapped error symbols like ✖ cause UI fragmentation.
**Action:** When outputting textual statuses with symbols, wrap them entirely in semantic colors (Green for success, Red for errors, Yellow for warnings) using centralized utilities (e.g., Colors.colorize) to improve scannability and UX consistency.
