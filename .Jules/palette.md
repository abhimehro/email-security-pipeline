## 2024-08-14 - Prevent terminal UI layout shifts
**Learning:** Terminal UI layout shifts occur when the initial static text (e.g., 'Loading...') doesn't match the structure of the dynamically updating frame (e.g., 'Loading: [progress_bar] [time]').
**Action:** When starting dynamic terminal loops (spinners, countdowns), ensure the initial static frame contains the formatted components to prevent horizontal visual shifts and improve screen reader experience.
