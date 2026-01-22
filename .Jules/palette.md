## 2025-05-26 - Interactive CLI Wait States
**Learning:** For CLI tools with long polling intervals, replacing `time.sleep()` with a visual countdown timer significantly improves perceived responsiveness and user confidence that the process hasn't hung.
**Action:** Use `sys.stdout.write` with `\r` (carriage return) for in-place updates, and always check `sys.stdout.isatty()` to gracefully degrade to `time.sleep` in non-interactive environments (CI/CD logs).
