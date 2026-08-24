## 2026-08-24 - Prevent terminal layout shifts in dynamic UX loops
**Learning:** When printing dynamic terminal text that updates via carriage return, standard length calculations fail because they count ANSI escape sequence characters. This causes the text to wrap visually and floods the terminal with new lines, breaking the loop UX.
**Action:** Use regex to strip ANSI escape sequences when calculating text length for terminal truncation.
