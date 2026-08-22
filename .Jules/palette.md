## 2024-11-20 - Dynamic Terminal Text Width Truncation
**Learning:** When printing dynamic terminal text (like a spinner message) ending with a carriage return (`\r`), lines that exceed the terminal width cause horizontal layout shifts and new line flooding caused by visual line wrapping.
**Action:** When creating text looping components using `\r`, truncate the message length to fit within the terminal's column width using `shutil.get_terminal_size().columns`.
