"""
UI utilities for the CLI.
Provides user-friendly output components like countdown timers.
"""

import itertools
import sys
import threading
import time

from .colors import Colors

import re
import shutil

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

def _truncate_for_terminal(text: str) -> str:
    """Truncates text to terminal width, ignoring ANSI escape sequences for length calculation."""
    # Leave 1 col padding to avoid accidental wrap on some terminals
    columns = shutil.get_terminal_size((80, 20)).columns - 1

    visual_length = 0
    result = []

    parts = ANSI_ESCAPE.split(text)
    escapes = ANSI_ESCAPE.findall(text)

    for i, part in enumerate(parts):
        if visual_length + len(part) > columns:
            allowed = columns - visual_length
            if allowed > 0:
                result.append(part[:allowed])
            break
        else:
            result.append(part)
            visual_length += len(part)

        if i < len(escapes):
            result.append(escapes[i])

    if visual_length < len(ANSI_ESCAPE.sub('', text)):
        # Ensure we don't leave hanging styles if we truncated
        return "".join(result) + "\033[0m"
    return "".join(result)

CURSOR_HIDE = "\033[?25l"
CURSOR_SHOW = "\033[?25h"
CTRL_C_HINT = " (Press Ctrl+C to stop)"


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

        # Format initial time based on duration to prevent layout shift
        if self.duration >= 60:
            initial_time = f"{self.duration // 60:02d}:{self.duration % 60:02d}"
        else:
            width = len(str(self.duration))
            initial_time = f"{self.duration:{width}d}s"

        # Accessibility & UX: Print an initial static frame so screen readers
        # have a chance to read the message and prevent layout shift before the loop.
        full_bar = "█" * self.PROGRESS_BAR_WIDTH
        colored_bar = Colors.colorize(full_bar, Colors.CYAN)
        line = f"{self.message}: {colored_bar} {initial_time}"
        sys.stdout.write(f"\r{_truncate_for_terminal(line)}\033[K")
        sys.stdout.flush()

        try:
            # Sleep briefly to ensure the screen reader announces it before the loop
            time.sleep(0.1)

            remaining = self.duration
            while remaining > 0 and not self._stop_event.is_set():
                # Format time as MM:SS if initial duration >= 60s, else just seconds
                if self.duration >= 60:
                    time_str = f"{remaining // 60:02d}:{remaining % 60:02d}"
                else:
                    width = len(str(self.duration))
                    time_str = f"{remaining:{width}d}s"

                # Progress bar
                pct = remaining / self.duration if self.duration > 0 else 0
                filled = int(pct * self.PROGRESS_BAR_WIDTH)
                progress_bar = "█" * filled + "░" * (self.PROGRESS_BAR_WIDTH - filled)
                colored_bar = Colors.colorize(progress_bar, Colors.CYAN)

                # \r moves cursor to start of line, \033[K clears the line
                line = f"{self.message}: {colored_bar} {time_str} "
                sys.stdout.write(f"\r{_truncate_for_terminal(line)}\033[K")
                sys.stdout.flush()

                time.sleep(self.interval)
                remaining -= int(self.interval)

            # Clear line after finish if not stopped early
            if not self._stop_event.is_set():
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()

        except (EOFError, KeyboardInterrupt):
            # Clean up line on interrupt
            warning = Colors.colorize("⚠", Colors.YELLOW)
            clean_msg = self.message.replace(
                Colors.colorize(" (Press Ctrl+C to stop)", Colors.GREY), ""
            ).replace(" (Press Ctrl+C to stop)", "")
            # Ensure we print the cancellation message correctly
            colored_msg = Colors.colorize(f"{clean_msg} (Cancelled)", Colors.YELLOW)
            sys.stdout.write(f"\r\033[K{warning} {colored_msg}\n")
            sys.stdout.flush()
            raise KeyboardInterrupt()
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
            if CTRL_C_HINT not in message:
                message += Colors.colorize(CTRL_C_HINT, Colors.GREY)
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
        # Accessibility: Sleep briefly to ensure the screen reader announces
        # the initial message before the loop starts rapidly redrawing.
        time.sleep(0.1)

        display_msg = self.message
        if sys.stdout.isatty() and CTRL_C_HINT not in display_msg:
            display_msg += Colors.colorize(CTRL_C_HINT, Colors.GREY)

        while self.busy:
            elapsed = time.time() - getattr(self, "start_time", time.time())
            time_str = Colors.colorize(f" [{elapsed:4.1f}s]", Colors.GREY)

            # \r moves cursor to start of line, \033[K clears the line
            spin_char = Colors.colorize(next(self.spinner), Colors.CYAN)
            line = f"{spin_char} {display_msg}{time_str}   "
            sys.stdout.write(f"\r{_truncate_for_terminal(line)}\033[K")
            sys.stdout.flush()
            time.sleep(self.delay)
            # Check again to avoid writing after stop
            if not self.busy:
                break

    def _get_tty_msg(self) -> str:
        if CTRL_C_HINT in self.message:
            return self.message
        return self.message + Colors.colorize(CTRL_C_HINT, Colors.GREY)

    def _get_non_tty_msg(self) -> str:
        return self.message if self.message.endswith("...") else f"{self.message}..."

    def __enter__(self):
        self.start_time = time.time()
        if sys.stdout.isatty():
            self._start_tty_spinner(self._get_tty_msg())
        else:
            print(self._get_non_tty_msg())
        return self

    def _start_tty_spinner(self, msg: str):
        """Helper to initialize the background spinner for interactive terminals."""
        # Hide cursor
        sys.stdout.write(CURSOR_HIDE)

        # Accessibility & UX: Print an initial static frame so screen readers
        # can read it, and include the elapsed time to prevent layout shift.
        initial_time = Colors.colorize(" [ 0.0s]", Colors.GREY)
        spin_char = Colors.colorize(next(self.spinner), Colors.CYAN)
        line = f"{spin_char} {msg}{initial_time}"
        sys.stdout.write(f"\r{_truncate_for_terminal(line)}\033[K")
        sys.stdout.flush()

        self.busy = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def _get_final_message_components(self, exc_type) -> tuple[str, str]:
        """Determine the final symbol and message to display."""
        clean_msg = self.message.replace(
            Colors.colorize(" (Press Ctrl+C to stop)", Colors.GREY), ""
        ).replace(" (Press Ctrl+C to stop)", "")
        is_cancelled = exc_type is not None and issubclass(
            exc_type, (EOFError, KeyboardInterrupt)
        )
        is_failed = exc_type is not None or self.fail_msg

        if is_cancelled:
            return "⚠", f"{clean_msg} (Cancelled)"

        if is_failed:
            msg = (
                self.fail_msg.replace(
                    Colors.colorize(" (Press Ctrl+C to stop)", Colors.GREY), ""
                ).replace(" (Press Ctrl+C to stop)", "")
                if self.fail_msg
                else clean_msg
            )
            return "✖", msg

        if self.success_msg:
            return "✔", self.success_msg.replace(
                Colors.colorize(" (Press Ctrl+C to stop)", Colors.GREY), ""
            ).replace(" (Press Ctrl+C to stop)", "")

        if self.persist:
            return "✔", clean_msg

        return "", ""

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - getattr(self, "start_time", time.time())
        raw_time_str = f" [{elapsed:4.1f}s]"

        symbol, msg = self._get_final_message_components(exc_type)

        if not symbol:
            self._cleanup_thread()
            if sys.stdout.isatty():
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                sys.stdout.write(CURSOR_SHOW)
                sys.stdout.flush()
            return

        if sys.stdout.isatty():
            self._cleanup_thread()
            time_str = (
                Colors.colorize(raw_time_str, Colors.GREY) if raw_time_str else ""
            )
            color = self._get_color_for_symbol(symbol)
            colored_symbol = Colors.colorize(symbol, color)

            # Apply the same semantic color to the message for visual consistency
            colored_msg = Colors.colorize(msg, color)

            sys.stdout.write(f"\r\033[K{colored_symbol} {colored_msg}{time_str}\n")
            sys.stdout.flush()
            sys.stdout.write(CURSOR_SHOW)
            sys.stdout.flush()
        else:
            sys.stdout.write(f"{symbol} {msg}{raw_time_str}\n")
            sys.stdout.flush()

    def _cleanup_thread(self):
        """Stop the spinner thread safely."""
        self.busy = False
        if self.thread:
            self.thread.join()

    def _get_color_for_symbol(self, symbol: str) -> str:
        """Map symbols to their respective colors."""
        if symbol == "⚠":
            return Colors.YELLOW
        if symbol == "✖":
            return Colors.RED
        if symbol == "✔":
            return Colors.GREEN
        return Colors.WHITE
