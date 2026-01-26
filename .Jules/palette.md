# Palette's Journal

## 2025-05-15 - Initial Assessment
**Learning:** This is a backend Python application (Email Security Analysis Pipeline) with no web frontend.
**Action:** UX improvements will focus on CLI output, log readability, and alert message formatting (the primary user interface for this tool).

## 2025-05-20 - Interactive CLI Onboarding
**Learning:** CLI tools often exit abruptly when configuration is missing, forcing users to context-switch to shell commands.
**Action:** Detect missing config and offer to create it interactively from a template within the application flow itself.

## 2025-10-27 - Positive Reinforcement in Security CLIs
**Learning:** Security tools often default to "silence is golden," but explicit "No issues detected" feedback builds trust and reduces anxiety for users interpreting logs.
**Action:** Always include success/clean states in report summaries, not just failure/threat states.

## 2025-11-20 - Visual Feedback for Blocking Operations
**Learning:** Users running connectivity checks often face "hanging" states where it's unclear if the tool is working or frozen, especially with network timeouts.
**Action:** Implement immediate visual feedback (e.g., "⏳ Checking...") before blocking network operations in CLI tools, using carriage returns (`\r`) to update status in-place.

## 2025-11-22 - Actionable Error Context
**Learning:** Generic error messages (e.g., "LOGIN failed") leave users stranded, especially for complex configs like Outlook business accounts vs. personal ones.
**Action:** Embed specific troubleshooting tips directly into the error output of CLI tools when known configuration pitfalls exist (e.g., "Tip: Personal Outlook accounts NO LONGER support App Passwords").

## 2026-01-26 - Signal Handling in UX Waits
**Learning:** When implementing "delightful" CLI waits (like countdowns), naively catching exceptions can swallow interrupt signals (Ctrl+C), leaving the user unable to exit the application gracefully.
**Action:** Always re-raise `KeyboardInterrupt` after cleaning up UI elements (like clearing the current line) to ensure the main event loop can handle the shutdown signal.
