"""
UI utilities for the CLI.
Provides user-friendly output components like countdown timers.
"""

import itertools
import sys
import threading
import time

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
        """Start the countdown timer."""
        if not sys.stdout.isatty():
            # In non-interactive mode, just wait
            time.sleep(self.duration)
            return

        # Hide cursor
        sys.stdout.write(CURSOR_HIDE)
        sys.stdout.flush()

        # Accessibility: Print an initial static line so screen readers
        # have a chance to read the message before we start rapidly
        # clearing and redrawing it with carriage returns.
        sys.stdout.write(f"{self.message}...")
        sys.stdout.flush()

        try:
            # Sleep briefly to ensure the screen reader announces it before the loop
            time.sleep(0.1)

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
                sys.stdout.write(f"\r{self.message}: {colored_bar} {time_str} \033[K")
                sys.stdout.flush()

                time.sleep(self.interval)
                remaining -= int(self.interval)

            # Clear line after finish if not stopped early
            if not self._stop_event.is_set():
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()

        except KeyboardInterrupt:
            # Clean up line on interrupt
            warning = Colors.colorize("⚠", Colors.YELLOW)
            clean_msg = self.message.replace(" (Press Ctrl+C to stop)", "")
            # Ensure we print the cancellation message correctly
            sys.stdout.write(f"\r\033[K{warning} {clean_msg} (Cancelled)\n")
            sys.stdout.flush()
            raise
        finally:
            # Restore cursor
            sys.stdout.write(CURSOR_SHOW)
            sys.stdout.flush()

    def stop(self):
        """Stop the countdown."""
        self._stop_event.set()

    @staticmethod
    def wait(seconds: int, message: str = "Waiting"):
        """Static convenience method to block with a countdown."""
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

    def __init__(
        self, message: str = "Loading", delay: float = 0.1, persist: bool = True
    ):
        self.spinner = itertools.cycle(
            ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        )
        self.message = message
        self.delay = delay
        self.persist = persist
        self.busy = False
        self.thread = None
        self.success_msg = None
        self.fail_msg = None

    def success(self, message: str):
        """Set a custom success message to display on completion."""
        self.success_msg = message

    def fail(self, message: str):
        """Set a custom failure message to display on error."""
        self.fail_msg = message

    def _spin(self):
        while self.busy:
            elapsed = time.time() - getattr(self, "start_time", time.time())
            time_str = (
                Colors.colorize(f" [{elapsed:.1f}s]", Colors.GREY)
                if elapsed >= 1.0
                else ""
            )
            # \r moves cursor to start of line, \033[K clears the line
            spin_char = Colors.colorize(next(self.spinner), Colors.CYAN)
            sys.stdout.write(f"\r{spin_char} {self.message}{time_str}   \033[K")
            sys.stdout.flush()
            time.sleep(self.delay)
            # Check again to avoid writing after stop
            if not self.busy:
                break

    def __enter__(self):
        self.start_time = time.time()
        msg = self.message if self.message.endswith("...") else f"{self.message}..."

        if sys.stdout.isatty():
            self._start_tty_spinner(msg)
        else:
            print(msg)
        return self

    def _start_tty_spinner(self, msg: str):
        """Helper to initialize the background spinner for interactive terminals."""
        # Hide cursor
        sys.stdout.write(CURSOR_HIDE)

        # Accessibility: Print an initial static line so screen readers
        # have a chance to read the message before we start rapidly
        # clearing and redrawing it with carriage returns.
        sys.stdout.write(msg)
        sys.stdout.flush()

        # Sleep briefly to ensure the screen reader announces it before the loop
        # Catch and skip so we just enter the spinner loop which handles cancellation gracefully
        try:
            time.sleep(0.1)
        except KeyboardInterrupt:
            pass

        self.busy = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - getattr(self, "start_time", time.time())
        time_str = (
            Colors.colorize(f" [{elapsed:.1f}s]", Colors.GREY) if elapsed >= 1.0 else ""
        )

        if sys.stdout.isatty():
            try:
                self.busy = False
                if self.thread:
                    self.thread.join()
                final_message = ""

                if exc_type is KeyboardInterrupt:
                    msg = self.message
                    warning = Colors.colorize("⚠", Colors.YELLOW)
                    final_message = f"{warning} {msg} (Cancelled){time_str}\n"
                elif exc_type is not None or self.fail_msg:
                    # Failure logic
                    msg = self.fail_msg if self.fail_msg else self.message
                    # Use Colors.colorize to ensure we get proper fallback if colors are disabled
                    cross = Colors.colorize("✘", Colors.RED)
                    final_message = f"{cross} {msg}{time_str}\n"
                elif self.success_msg:
                    # Explicit success message always persists
                    check = Colors.colorize("✔", Colors.GREEN)
                    final_message = f"{check} {self.success_msg}{time_str}\n"
                elif self.persist:
                    # Default persistence
                    check = Colors.colorize("✔", Colors.GREEN)
                    final_message = f"{check} {self.message}{time_str}\n"

                sys.stdout.write(f"\r\033[K{final_message}")
                sys.stdout.flush()
            finally:
                # Restore cursor
                sys.stdout.write(CURSOR_SHOW)
                sys.stdout.flush()
        else:
            # Non-TTY: provide simple success/failure feedback without ANSI codes.
            # Colors.ENABLED is computed at import time, so use plain symbols here
            # to avoid leaking escape sequences when stdout is redirected later.
            raw_time_str = f" [{elapsed:.1f}s]" if elapsed >= 1.0 else ""
            if exc_type is KeyboardInterrupt:
                sys.stdout.write(f"⚠ {self.message} (Cancelled){raw_time_str}\n")
            elif exc_type is not None or self.fail_msg:
                msg = self.fail_msg if self.fail_msg else self.message
                sys.stdout.write(f"✘ {msg}{raw_time_str}\n")
            elif self.success_msg:
                sys.stdout.write(f"✔ {self.success_msg}{raw_time_str}\n")
            elif self.persist:
                sys.stdout.write(f"✔ {self.message}{raw_time_str}\n")
            sys.stdout.flush()
