## 2024-05-18 - [Terminal Truncation UX]
**Learning:** Dynamic terminal strings (like spinners and progress bars) that exceed the terminal width cause severe horizontal layout shifts and screen flashing due to unwanted visual line wrapping. Standard `len()` checks fail because they count invisible ANSI color codes.
**Action:** When printing dynamic terminal text with carriage returns (`\r`), strip ANSI escape sequences before checking string length, and truncate the visible text (appending `…`) to fit within `shutil.get_terminal_size().columns`.
