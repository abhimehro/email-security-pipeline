"""
UI utilities for the CLI.
Provides user-friendly output components like countdown timers.
"""

import sys
import time
import threading
import itertools

from .colors import Colors

CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"


class CountdownTimer:
    """
    Displays a countdown timer in the terminal.
    Handles TTY checking and graceful interruptions.
    """

    PROGRESS_BAR_WIDTH = 20

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

        # Hide cursor
        sys.stdout.write(CURSOR_HIDE)
        sys.stdout.flush()

        try:
            remaining = self.duration
            while remaining > 0 and not self._stop_event.is_set():
                # Format time as MM:SS if > 60s, else just seconds
                if remaining >= 60:
                    time_str = f"{remaining // 60}:{remaining % 60:02d}"
                else:
                    time_str = f"{remaining}s"

                # Progress bar
                pct = remaining / self.duration if self.duration > 0 else 0
                filled = int(pct * self.PROGRESS_BAR_WIDTH)
                progress_bar = "█" * filled + "░" * (self.PROGRESS_BAR_WIDTH - filled)
                colored_bar = Colors.colorize(progress_bar, Colors.CYAN)

                # \r moves cursor to start of line, \033[K clears the line
                sys.stdout.write(
                    f"\r{self.message}: {colored_bar} {time_str} \033[K"
                )
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
        finally:
            # Restore cursor
            sys.stdout.write(CURSOR_SHOW)
            sys.stdout.flush()

    def stop(self):
        """Stop the countdown"""
        self._stop_event.set()

    @staticmethod
    def wait(seconds: int, message: str = "Waiting"):
        """Static convenience method to block with a countdown"""
        # Only add the interactive hint when we're actually in a TTY.
        # In non-TTY mode, `start()` will just sleep and never render the message.
        if sys.stdout.isatty():
            hint = " (Press Ctrl+C to stop)"
            if hint not in message:
                message += hint
        timer = CountdownTimer(seconds, message)
        timer.start()


class Spinner:
    """
    Displays a loading spinner in the terminal.
    """
    def __init__(self, message: str = "Loading", delay: float = 0.1, persist: bool = True):
        self.spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        self.message = message
        self.delay = delay
        self.persist = persist
        self.busy = False
        self.thread = None
        self.success_msg = None
        self.fail_msg = None

    def success(self, message: str):
        """Set a custom success message to display on completion"""
        self.success_msg = message

    def fail(self, message: str):
        """Set a custom failure message to display on error"""
        self.fail_msg = message

    def _spin(self):
        while self.busy:
            # \r moves cursor to start of line, \033[K clears the line
            spin_char = Colors.colorize(next(self.spinner), Colors.CYAN)
            sys.stdout.write(f"\r{spin_char} {self.message}   \033[K")
            sys.stdout.flush()
            time.sleep(self.delay)
            # Check again to avoid writing after stop
            if not self.busy:
                break

    def __enter__(self):
        if sys.stdout.isatty():
            # Hide cursor
            sys.stdout.write(CURSOR_HIDE)
            sys.stdout.flush()

            self.busy = True
            self.thread = threading.Thread(target=self._spin)
            self.thread.start()
        else:
            print(f"{self.message}...")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if sys.stdout.isatty():
            try:
                self.busy = False
                if self.thread:
                    self.thread.join()
                final_message = ""

                if exc_type is not None:
                    # Failure logic
                    msg = self.fail_msg if self.fail_msg else self.message
                    # Use Colors.colorize to ensure we get proper fallback if colors are disabled
                    cross = Colors.colorize("✘", Colors.RED)
                    final_message = f"{cross} {msg}\n"
                elif self.success_msg:
                    # Explicit success message always persists
                    check = Colors.colorize("✔", Colors.GREEN)
                    final_message = f"{check} {self.success_msg}\n"
                elif self.persist:
                    # Default persistence
                    check = Colors.colorize("✔", Colors.GREEN)
                    final_message = f"{check} {self.message}\n"

                sys.stdout.write(f"\r\033[K{final_message}")
                sys.stdout.flush()
            finally:
                # Restore cursor
                sys.stdout.write(CURSOR_SHOW)
                sys.stdout.flush()
        else:
            # Non-TTY: provide simple success/failure feedback
            if exc_type is not None:
                msg = self.fail_msg if self.fail_msg else self.message
                # Colorize logic handles whether it's enabled or not
                cross = Colors.colorize("✘", Colors.RED)
                sys.stdout.write(f"{cross} {msg}\n")
            elif self.success_msg:
                check = Colors.colorize("✔", Colors.GREEN)
                sys.stdout.write(f"{check} {self.success_msg}\n")
            elif self.persist:
                check = Colors.colorize("✔", Colors.GREEN)
                sys.stdout.write(f"{check} {self.message}\n")
            sys.stdout.flush()
