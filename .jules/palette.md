## 2024-07-04 - Standardizing Terminal Cross Marks
**Learning:** The heavy ballot cross `✘` (U+2718) is poorly aligned and supported in some monospaced terminal fonts compared to the heavy multiplication cross `✖` (U+2716), which is vertically centered and more distinct.
**Action:** Always prefer `✖` over `✘` when rendering error indicators or negative states in text-based CLI applications.

## 2024-07-04 - Explicit Exit Affordances in CLI Prompts
**Learning:** Users often get stuck in terminal prompts (like `[Y/n]`) if they want to exit but don't know the `Ctrl+C` interrupt shortcut. Implicit exits create friction.
**Action:** Always explicitly document `q` or `quit` as an option in terminal prompts (e.g., `[Y/n/q]`) and map them to a graceful termination (like raising `KeyboardInterrupt`) to reduce cognitive load and improve user autonomy.
