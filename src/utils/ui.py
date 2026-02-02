"""
UI utilities for the CLI.
Provides user-friendly output components like countdown timers.
"""

import sys
import time
import threading


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

                # \r moves cursor to start of line, \033[K clears the line
                sys.stdout.write(f"\r{self.message}: {time_str} ... \033[K")
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


class ProgressBar:
    """
    Simple text-based progress bar.
    Usage:
        with ProgressBar(total=10, prefix="Processing") as pb:
            for item in items:
                process(item)
                pb.update(1, suffix=item.name)
    """
    def __init__(self, total: int, prefix: str = "", length: int = 30, fill: str = "█"):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.fill = fill
        self.iteration = 0
        self.is_tty = sys.stdout.isatty()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.is_tty:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def update(self, advance: int = 1, suffix: str = ""):
        self.iteration += advance
        if not self.is_tty:
            return

        percent = ("{0:.1f}").format(100 * (self.iteration / float(self.total)))
        filled_length = int(self.length * self.iteration // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)

        # \r to return to start, \033[K to clear line
        # Truncate suffix if too long to prevent wrapping
        if len(suffix) > 40:
            suffix = suffix[:37] + "..."

        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent}% {suffix}\033[K')
        sys.stdout.flush()
