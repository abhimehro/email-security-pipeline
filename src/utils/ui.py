"""
UI utilities for the CLI.
Provides user-friendly output components like countdown timers.
"""

import itertools
import re
import shutil
import sys
import threading
import time

from .colors import Colors

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _truncate_ansi_parts(parts: list[str], escapes: list[str], columns: int) -> str:
    """Helper to truncate ANSI-formatted text parts to fit within terminal column width."""
    current_length = 0
    result = []

    for i, part in enumerate(parts):
        if current_length + len(part) > columns:
            allowed = columns - current_length
            if allowed > 0:
                result.append(part[:allowed])
            break

        result.append(part)
        current_length += len(part)

        if i < len(escapes):
            result.append(escapes[i])

    return "".join(result) + "\033[0m"


def _truncate_for_terminal(text: str) -> str:
    """Truncates text to terminal width, ignoring ANSI escape sequences for length calculation."""
    # Leave 1 col padding to avoid accidental wrap on some terminals
    columns = shutil.get_terminal_size((80, 20)).columns - 1

    # ⚡ BOLT: Fast path for non-ANSI text to bypass regex parsing and list reconstruction
    if "\x1b" not in text:
        if len(text) <= columns:
            return text
        return text[:columns] + "\033[0m"

    parts = ANSI_ESCAPE.split(text)

    # ⚡ BOLT: Fast path if non-ANSI visual length fits within terminal columns
    if sum(len(part) for part in parts) <= columns:
        return text

    escapes = ANSI_ESCAPE.findall(text)
    return _truncate_ansi_parts(parts, escapes, columns)


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

    def _get_display_msg(self) -> str:
        """Ensure keyboard interrupt hint is displayed when running in an interactive TTY."""
        display_msg = self.message
        if CTRL_C_HINT not in display_msg:
            display_msg += Colors.colorize(CTRL_C_HINT, Colors.GREY)
        return display_msg

    def _format_time_str(self, remaining: int) -> str:
        """Format remaining time as MM:SS if duration >= 60s, else seconds."""
        if self.duration >= 60:
            return f"{remaining // 60:02d}:{remaining % 60:02d}"
        width = len(str(self.duration))
        return f"{remaining:{width}d}s"

    def _render_progress_bar(self, remaining: int) -> str:
        """Render colored progress bar based on remaining time."""
        pct = remaining / self.duration if self.duration > 0 else 0
        filled = int(pct * self.PROGRESS_BAR_WIDTH)
        progress_bar = "█" * filled + "░" * (self.PROGRESS_BAR_WIDTH - filled)
        return Colors.colorize(progress_bar, Colors.CYAN)

    def _write_line(self, line: str) -> None:
        """Write truncated line to stdout with carriage return and line clear."""
        sys.stdout.write(f"\r{_truncate_for_terminal(line)}\033[K")
        sys.stdout.flush()

    def _handle_interrupt(self) -> None:
        """Clean up line and print cancellation message on interrupt."""
        warning = Colors.colorize("⚠", Colors.YELLOW)
        clean_msg = self.message.replace(
            Colors.colorize(CTRL_C_HINT, Colors.GREY), ""
        ).replace(CTRL_C_HINT, "")
        colored_msg = Colors.colorize(f"{clean_msg} (Cancelled)", Colors.YELLOW)
        sys.stdout.write(f"\r\033[K{warning} {colored_msg}\n")
        sys.stdout.flush()

    def start(self):
        """Start the countdown timer."""
        if not sys.stdout.isatty():
            time.sleep(self.duration)
            return

        sys.stdout.write(CURSOR_HIDE)
        sys.stdout.flush()

        display_msg = self._get_display_msg()
        initial_time = self._format_time_str(self.duration)
        full_bar = Colors.colorize("█" * self.PROGRESS_BAR_WIDTH, Colors.CYAN)
        self._write_line(f"{display_msg}: {full_bar} {initial_time}")

        try:
            time.sleep(0.1)
            remaining = self.duration
            while remaining > 0 and not self._stop_event.is_set():
                time_str = self._format_time_str(remaining)
                bar = self._render_progress_bar(remaining)
                self._write_line(f"{display_msg}: {bar} {time_str} ")

                time.sleep(self.interval)
                remaining -= int(self.interval)

            if not self._stop_event.is_set():
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()

        except (EOFError, KeyboardInterrupt):
            self._handle_interrupt()
            raise KeyboardInterrupt()
        finally:
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
