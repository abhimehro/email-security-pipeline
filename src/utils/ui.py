"""
UI utilities for the CLI.
Provides user-friendly output components like countdown timers.
"""

import sys
import time
import threading
from .colors import Colors


class CountdownTimer:
    """
    Displays a countdown timer in the terminal.
    Handles TTY checking and graceful interruptions.
    """

    def __init__(self, duration: int, message: str = "Waiting", interval: float = 1.0):
        self.duration = duration
        self.message = message
        self.interval = interval
        self._stop_event = threading.Event()

    def start(self):
        """Start the countdown timer"""
        if not sys.stdout.isatty():
            # In non-interactive mode, just wait
            time.sleep(self.duration)
            return

        try:
            remaining = self.duration
            while remaining > 0 and not self._stop_event.is_set():
                # Format time as MM:SS if > 60s, else just seconds
                if remaining >= 60:
                    time_str = f"{remaining // 60}:{remaining % 60:02d}"
                else:
                    time_str = f"{remaining}s"

                # Progress Bar
                total_len = 20
                if self.duration > 0:
                    percent = remaining / self.duration
                else:
                    percent = 0

                filled_len = int(percent * total_len)
                # Ensure filled_len is within bounds
                filled_len = max(0, min(filled_len, total_len))

                bar = "█" * filled_len + "░" * (total_len - filled_len)
                colored_bar = Colors.colorize(bar, Colors.CYAN)

                # \r moves cursor to start of line, \033[K clears the line
                # Added brackets around bar for better visual containment
                sys.stdout.write(f"\r{self.message}: [{colored_bar}] {time_str} ... \033[K")
                sys.stdout.flush()

                time.sleep(self.interval)
                remaining -= int(self.interval)

            # Clear line after finish if not stopped early
            if not self._stop_event.is_set():
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()

        except KeyboardInterrupt:
            # Clean up line on interrupt
            sys.stdout.write("\n")
            sys.stdout.flush()
            raise

    def stop(self):
        """Stop the countdown"""
        self._stop_event.set()

    @staticmethod
    def wait(seconds: int, message: str = "Waiting"):
        """Static convenience method to block with a countdown"""
        timer = CountdownTimer(seconds, message)
        timer.start()
