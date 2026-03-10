"""
Alert and Response System
Handles threat notifications and alerting across multiple channels
"""

import asyncio
import logging
import re
import threading
import requests
import unicodedata
import shutil
import textwrap
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..utils.sanitization import sanitize_for_csv
from .email_data import EmailData
from .spam_analyzer import SpamAnalysisResult
from .nlp_analyzer import NLPAnalysisResult
from .media_analyzer import MediaAnalysisResult
from ..utils.colors import Colors
from ..utils.security_validators import is_safe_webhook_url

# Regex pattern for stripping ANSI codes (compiled once for performance)
ANSI_PATTERN = re.compile(r'\x1b\[[0-9;]*m')

# Regex pattern for extracting URLs from error messages (compiled once for performance)
# Expanded to catch bare paths/hosts for complete redaction when scheme is missing.
URL_PATTERN = re.compile(r'(?:https?://[^\s<>"]+|www\.[^\s<>"]+|/[^\s<>"]+)')


@dataclass
class ThreatReport:
    """Comprehensive threat report"""
    email_id: str
    subject: str
    sender: str
    recipient: str
    date: str
    overall_threat_score: float
    risk_level: str
    spam_analysis: Dict
    nlp_analysis: Dict
    media_analysis: Dict
    recommendations: List[str]
    timestamp: str


class AlertSystem:
    """Manages alerts and notifications"""

    # Common prefixes for recommendations to strip during display to prevent duplication
    RECOMMENDATION_PREFIXES = ["⚠️ ", "🎣 ", "🔗 ", "⏰ ", "📎 ", "👤 "]

    # Pre-allocated tuple for fast C-level execution of startswith()
    RECOMMENDATION_PREFIXES_TUPLE = tuple(RECOMMENDATION_PREFIXES)

    # Compiled regex patterns for fast substring keyword checks in recommendations.
    # Use compile_patterns for consistency and centralized safety checks across modules.
    RED_KEYWORDS_PATTERN, = compile_patterns([r'HIGH RISK|DANGEROUS|PHISHING'])
    YELLOW_KEYWORDS_PATTERN, = compile_patterns([r'SUSPICIOUS|VERIFY|URGENCY|IMPERSONATION'])

    # Maximum number of items shown per section in the console threat report.
    # Helps keep the output readable; lists may be truncated in the console view.
    MAX_SPAM_INDICATORS_DISPLAY = 5
    MAX_NLP_INDICATORS_DISPLAY = 3
    MAX_MEDIA_WARNINGS_DISPLAY = 3

    # Maximum dispatch attempts per alert before giving up (worker mode).
    MAX_DISPATCH_RETRIES = 3

    # Maximum number of pending alerts the queue will hold.  When full, new
    # alerts are dropped (with an error log) rather than blocking the pipeline.
    # Tune this value if endpoints are consistently slow or unavailable for
    # longer than ALERT_QUEUE_MAX_SIZE * mean-dispatch-time seconds.
    ALERT_QUEUE_MAX_SIZE = 1000

    # Fallback recommendation text used by _generate_recommendations when no
    # specific threat condition is matched.  Defined as a class constant so
    # tests can reference it without hardcoding the string in two places.
    DEFAULT_CLEAN_RECOMMENDATION = "Review email carefully before taking action"

    def __init__(self, config):
        """
        Initialize alert system

        Args:
            config: AlertConfig object
        """
        self.config = config
        self.logger = logging.getLogger("AlertSystem")

        # Async alert queue infrastructure.
        # The event loop and queue are created inside _run_worker_loop() so they
        # live in the worker thread.  All three attributes are set/read across
        # threads.  In CPython the GIL makes simple attribute reads/writes on
        # built-in types effectively atomic; however this is a CPython
        # implementation detail.  If the code is ever ported to a free-threaded
        # runtime (e.g. Python 3.13+ with --disable-gil) explicit locking should
        # be added around these references.
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._alert_queue: Optional[asyncio.Queue] = None
        self._worker_thread: Optional[threading.Thread] = None
        # Signals that the queue is ready to accept alerts.
        self._queue_ready = threading.Event()

    def start_worker(self) -> None:
        """Start the background alert worker in a dedicated thread with its own event loop.

        Call this once before processing emails so that alerts are dispatched
        asynchronously without blocking the main pipeline.  Idempotent – safe to
        call multiple times; a second call while the worker is alive is a no-op.
        """
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._queue_ready.clear()
        self._worker_thread = threading.Thread(
            target=self._run_worker_loop,
            daemon=True,
            name="alert-worker",
        )
        self._worker_thread.start()

        # Block the caller briefly until the queue is ready so the first
        # send_alert() call is guaranteed to see a live queue.
        if not self._queue_ready.wait(timeout=5):
            self.logger.warning("Alert worker did not become ready within 5 s")

    def stop_worker(self) -> None:
        """Gracefully stop the alert worker, flushing all queued alerts first.

        Sends a sentinel ``None`` value into the queue, waits for the worker
        coroutine to drain the remaining items, then joins the thread.
        Zero alerts are lost as long as the join completes within the timeout.
        """
        loop = self._loop
        queue = self._alert_queue
        if loop is None or queue is None or loop.is_closed():
            return

        try:
            # Enqueue the stop sentinel.
            fut = asyncio.run_coroutine_threadsafe(queue.put(None), loop)
            fut.result(timeout=5)
        except Exception as exc:
            self.logger.error("Error sending stop sentinel to alert worker: %s", exc)
            return

        thread = self._worker_thread
        if thread:
            thread.join(timeout=30)
            if thread.is_alive():
                self.logger.warning("Alert worker did not stop within 30 s")

    def _run_worker_loop(self) -> None:
        """Entry point for the worker thread: creates the event loop and queue, then runs the worker."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._alert_queue = asyncio.Queue(maxsize=self.ALERT_QUEUE_MAX_SIZE)
        self._queue_ready.set()
        try:
            loop.run_until_complete(self._alert_worker())
        finally:
            # Always close the loop first to release event loop resources.
            loop.close()
            # After the loop is closed, clear references so callers don't see
            # a "zombie" worker (queue bound to a closed loop, dead thread, etc.).
            self._loop = None
            self._alert_queue = None
            # Reset the readiness event so future restarts can't misinterpret
            # a set event as meaning "worker is currently running".
            self._queue_ready.clear()
            # If this instance is still tracking this thread as the worker,
            # clear it. The identity check avoids clobbering a newer worker
            # thread in case of rapid restart while shutdown is in progress.
            if getattr(self, "_worker_thread", None) is threading.current_thread():
                self._worker_thread = None

    async def _alert_worker(self) -> None:
        """Background coroutine: dequeues alerts and dispatches them with timeout + retry.

        Alert ordering is preserved because asyncio.Queue is FIFO.
        Each alert gets up to MAX_DISPATCH_RETRIES attempts with exponential
        backoff (1 s, 2 s, 4 s …).  After all retries are exhausted the alert
        is dropped and an error is logged (preventing indefinite blocking).
        """
        assert self._alert_queue is not None  # set before event loop starts

        while True:
            report = await self._alert_queue.get()
            if report is None:
                # Sentinel received – drain complete, stop worker.
                self._alert_queue.task_done()
                break

            dispatched = False
            for attempt in range(self.MAX_DISPATCH_RETRIES):
                try:
                    await asyncio.wait_for(
                        self._dispatch_alert_async(report), timeout=10.0
                    )
                    dispatched = True
                    break
                except asyncio.TimeoutError:
                    self.logger.error(
                        "Alert dispatch timed out for email %s (attempt %d/%d)",
                        report.email_id, attempt + 1, self.MAX_DISPATCH_RETRIES,
                    )
                except Exception as exc:
                    self.logger.error(
                        "Alert dispatch failed for email %s (attempt %d/%d): %s",
                        report.email_id, attempt + 1, self.MAX_DISPATCH_RETRIES, exc,
                    )

                if attempt < self.MAX_DISPATCH_RETRIES - 1:
                    # Exponential backoff: 1 s → 2 s → 4 s
                    await asyncio.sleep(2 ** attempt)

            if not dispatched:
                self.logger.error(
                    "Alert permanently failed for email %s after %d attempts",
                    report.email_id, self.MAX_DISPATCH_RETRIES,
                )

            self._alert_queue.task_done()

    async def _dispatch_alert_async(self, report: ThreatReport) -> None:
        """Dispatch a single alert through all configured channels (async wrapper).

        Each synchronous I/O call (_webhook_alert, _slack_alert) is offloaded to
        the default executor so the event loop is never blocked.  Raises
        RuntimeError if any configured channel fails so the caller (_alert_worker)
        can apply retry logic.
        """
        loop = asyncio.get_running_loop()
        failed_channels = []

        # Console output is fast (no I/O); run directly in event loop thread.
        if self.config.console:
            self._console_alert(report)

        if self.config.webhook_enabled and self.config.webhook_url:
            ok = await loop.run_in_executor(None, self._webhook_alert, report)
            if not ok:
                failed_channels.append("webhook")

        if self.config.slack_enabled and self.config.slack_webhook:
            ok = await loop.run_in_executor(None, self._slack_alert, report)
            if not ok:
                failed_channels.append("slack")

        if failed_channels:
            raise RuntimeError(
                f"Alert dispatch failed for channels: {', '.join(failed_channels)}"
            )

    def _dispatch_alert_sync(self, report: ThreatReport) -> None:
        """Synchronous alert dispatch used as a fallback when the worker is not running."""
        if self.config.console:
            self._console_alert(report)

        if self.config.webhook_enabled and self.config.webhook_url:
            self._webhook_alert(report)

        if self.config.slack_enabled and self.config.slack_webhook:
            self._slack_alert(report)

    def send_alert(self, threat_report: ThreatReport):
        """
        Queue an alert for non-blocking async dispatch.

        If the background worker is running the alert is enqueued and this
        method returns in < 1 ms (fire-and-forget).  If the worker has not been
        started (e.g. in tests or single-shot scripts) the alert is dispatched
        synchronously so no alerts are silently dropped.

        Args:
            threat_report: Threat report to alert on
        """
        # Only alert on significant threats
        if threat_report.overall_threat_score < self.config.threat_low:
            self.logger.debug(
                "Threat score too low to alert: %s", threat_report.overall_threat_score
            )
            # Provide positive feedback for clean emails if console is enabled
            if self.config.console:
                self._console_clean_report(threat_report)
            return

        loop = self._loop
        queue = self._alert_queue

        if loop is not None and queue is not None and not loop.is_closed():
            # Fire-and-forget: non-blocking enqueue then return immediately.
            # put_nowait raises asyncio.QueueFull if the queue is at capacity
            # (capped at ALERT_QUEUE_MAX_SIZE); the exception propagates as a
            # Future error and is surfaced via _on_enqueue_done so operators
            # see dropped alerts in logs without the pipeline being blocked.
            async def _do_enqueue():
                queue.put_nowait(threat_report)

            fut = asyncio.run_coroutine_threadsafe(_do_enqueue(), loop)
            fut.add_done_callback(self._on_enqueue_done)
        else:
            # Worker not started: synchronous fallback (no alerts lost).
            self._dispatch_alert_sync(threat_report)

    def _on_enqueue_done(self, fut) -> None:
        """Callback invoked when the enqueue Future completes; logs unexpected errors.

        Note: fut.exception() raises asyncio.CancelledError if the Future was cancelled,
        which is expected during shutdown. We handle that explicitly so this callback
        never raises and doesn't pollute logs or mask the original shutdown reason.
        """
        try:
            exc = fut.exception()
        except asyncio.CancelledError:
            # Cancellation is expected when the event loop or worker is shutting down;
            # treat this as a benign condition and avoid logging it as an error.
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Alert enqueue future was cancelled (likely during shutdown).")
            return
        except Exception as unexpected:
            # Defensive: if checking the Future's exception itself fails, log that
            # rather than letting the callback raise and hide the root cause.
            self.logger.error(
                "Unexpected error while inspecting enqueue future: %s",
                unexpected,
                exc_info=unexpected,
            )
            return
        if exc is not None:
            if isinstance(exc, asyncio.QueueFull):
                self.logger.error(
                    "Alert queue is full (%d items); alert dropped. "
                    "Consider increasing ALERT_QUEUE_MAX_SIZE or "
                    "investigating slow/unavailable webhook endpoints.",
                    self.ALERT_QUEUE_MAX_SIZE,
                )
            else:
                self.logger.error("Failed to enqueue alert: %s", exc)

    def _print_alert_row(self, text: str, risk_color: str, indent: int = 0):
        """Helper to print a row with the left border"""
        # Note: We don't print the right border '│' because calculating visual width
        # with ANSI codes and unicode/emojis is complex without external dependencies.
        # The design uses an open-sided card metaphor for text rows.
        prefix = Colors.colorize("│", risk_color) + " " * (2 + indent)
        print(f"{prefix}{text}")

    def _print_alert_header(self, risk_level: str, timestamp: str, width: int, risk_color: str, risk_symbol: str):
        """Print the alert header"""
        print()
        # Top Border (┌───┐)
        # Width adjustment: -2 for the corners
        border_len = width - 2
        print(Colors.colorize(f"┌{'─'*border_len}┐", risk_color))

        # Header Row
        title = "🚨 SECURITY ALERT"
        risk_label = f"{risk_level.upper()} RISK"

        # Padding calculation:
        # Width - (left_border + space) - title_len - padding - risk_label_len - (space + symbol + right_border)
        # Visual estimation:
        # │  (3 chars visual)
        # title (~18 chars visual with emoji)
        # risk_label (variable)
        # symbol (1-2 chars visual)
        # right_border (not printed in header row in original, but let's add it if we can align)

        # Simpler approach for header: Just use the same layout but maybe without the right border for the text row
        # strictly if alignment is hard. But the PR comment asked for closed borders.
        # Let's try to close the top/bottom/separators first as requested.

        # Padding for the header text row:
        # We need to fill the space between title and risk label.
        # Fixed width = width
        # Content = "│  " + title + PADDING + risk_label + " " + symbol
        # We don't print a right border '│' here because alignment is tricky with emojis.
        # But we can try to approximate.

        # Magic number explanation:
        # 5 comes from: 3 chars for left prefix ("│  ") + 1 char space before symbol + 1 char approx for symbol/emoji width variance
        padding_len = width - len(title) - len(risk_label) - 5
        padding = " " * max(1, padding_len)

        print(
            Colors.colorize("│  ", risk_color) +
            Colors.colorize(title, Colors.BOLD) +
            padding +
            Colors.colorize(risk_label, risk_color + Colors.BOLD) +
            " " + risk_symbol
        )

        # Separator (├───┤)
        print(Colors.colorize(f"├{'─'*border_len}┤", risk_color))

    def _print_alert_metadata(self, report: ThreatReport, width: int, risk_color: str, formatted_time: str):
        """Print alert metadata (Timestamp, Subject, From, To)"""
        max_field_len = width - 15

        def safe_field(val):
            s = self._sanitize_text(val, csv_safe=True)
            if len(s) > max_field_len:
                return s[:max_field_len-3] + "..."
            return s

        self._print_alert_row(f"{Colors.BOLD}Timestamp:{Colors.RESET} {formatted_time}", risk_color)
        self._print_alert_row(f"{Colors.BOLD}Subject:{Colors.RESET}   {safe_field(report.subject)}", risk_color)
        self._print_alert_row(f"{Colors.BOLD}From:{Colors.RESET}      {safe_field(report.sender)}", risk_color)
        self._print_alert_row(f"{Colors.BOLD}To:{Colors.RESET}        {safe_field(report.recipient)}", risk_color)
        self._print_alert_row("", risk_color)

    def _print_threat_score(self, score: float, risk_level: str, width: int, risk_color: str):
        """Print the threat score and progress bar"""
        score_val = min(max(score, 0), 100)
        meter_len = 40
        filled_len = int(score_val / 100 * meter_len)
        bar = "█" * filled_len + "░" * (meter_len - filled_len)
        meter_color = Colors.get_risk_color(risk_level)

        self._print_alert_row(f"{Colors.BOLD}THREAT SCORE:{Colors.RESET} {score:.2f}/100", risk_color)
        self._print_alert_row(f"{Colors.colorize(bar, meter_color)}", risk_color)

    def _print_analysis_details(self, report: ThreatReport, width: int, risk_color: str):
        """Print detailed analysis sections"""
        border_len = width - 2
        print(Colors.colorize(f"├{'─'*border_len}┤", risk_color))
        self._print_alert_row(Colors.colorize("ANALYSIS DETAILS", Colors.BOLD), risk_color)
        self._print_alert_row("", risk_color)

        # Helper for analysis sections
        def print_section_header(title, analysis_data):
            level = analysis_data.get('risk_level', 'unknown')
            color = Colors.get_risk_color(level)
            symbol = Colors.get_risk_symbol(level)
            self._print_alert_row(f"{Colors.BOLD}{title}:{Colors.RESET} {Colors.colorize(level.upper(), color)} {symbol}", risk_color)

        # Spam
        print_section_header("📧 SPAM", report.spam_analysis)
        if report.spam_analysis.get('indicators'):
            for indicator in report.spam_analysis['indicators'][:self.MAX_SPAM_INDICATORS_DISPLAY]:
                self._print_alert_row(f"{Colors.colorize('•', Colors.GREY)} {indicator}", risk_color, indent=3)
        else:
            self._print_alert_row(f"{Colors.colorize('✓', Colors.GREEN)} No suspicious patterns", risk_color, indent=3)
        self._print_alert_row("", risk_color)

        # NLP
        print_section_header("🧠 NLP", report.nlp_analysis)
        nlp = report.nlp_analysis
        has_nlp = False
        if nlp.get('social_engineering_indicators'):
            self._print_alert_row(f"{Colors.BOLD}Social Engineering:{Colors.RESET}", risk_color, indent=3)
            for ind in nlp['social_engineering_indicators'][:self.MAX_NLP_INDICATORS_DISPLAY]:
                self._print_alert_row(f"{Colors.colorize('•', Colors.RED)} {ind}", risk_color, indent=5)
            has_nlp = True

        if nlp.get('authority_impersonation'):
            self._print_alert_row(f"{Colors.BOLD}Authority Impersonation:{Colors.RESET}", risk_color, indent=3)
            for ind in nlp['authority_impersonation'][:self.MAX_NLP_INDICATORS_DISPLAY]:
                self._print_alert_row(f"{Colors.colorize('•', Colors.RED)} {ind}", risk_color, indent=5)
            has_nlp = True

        if not has_nlp:
            self._print_alert_row(f"{Colors.colorize('✓', Colors.GREEN)} No social engineering or impersonation detected", risk_color, indent=3)
        self._print_alert_row("", risk_color)

        # Media
        print_section_header("📎 MEDIA", report.media_analysis)
        media = report.media_analysis
        if media.get('file_type_warnings'):
            self._print_alert_row(f"{Colors.BOLD}File Warnings:{Colors.RESET}", risk_color, indent=3)
            for warning in media['file_type_warnings'][:self.MAX_MEDIA_WARNINGS_DISPLAY]:
                self._print_alert_row(f"{Colors.colorize('•', Colors.YELLOW)} {warning}", risk_color, indent=5)
        else:
            self._print_alert_row(f"{Colors.colorize('✓', Colors.GREEN)} Attachments appear safe", risk_color, indent=3)

    def _print_recommendations(self, recommendations: List[str], width: int, risk_color: str):
        """Print recommendations section"""
        border_len = width - 2
        print(Colors.colorize(f"├{'─'*border_len}┤", risk_color))
        self._print_alert_row(Colors.colorize("RECOMMENDATIONS", Colors.BOLD), risk_color)
        self._print_alert_row("", risk_color)

        for rec in recommendations:
            color = Colors.GREEN
            rec_upper = rec.upper()
            icon = "►"

            # Remove existing prefixes to prevent double icons
            # Optimization: tuple-based startswith executes entirely in C and avoids Python loop overhead
            # We still need to find which prefix matched to slice it correctly, but the initial
            # fast check filters out the vast majority of cases instantly.
            if rec.startswith(self.RECOMMENDATION_PREFIXES_TUPLE):
                for prefix in self.RECOMMENDATION_PREFIXES:
                    if rec.startswith(prefix):
                        rec = rec[len(prefix):]
                        break

            # Optimization: compiled regex search is faster than any() generator loop for substring matching
            if self.RED_KEYWORDS_PATTERN.search(rec_upper):
                color = Colors.RED
            elif self.YELLOW_KEYWORDS_PATTERN.search(rec_upper):
                color = Colors.YELLOW

            # Calculate available width for text
            # Width - 2 (left border/space) - 3 (icon + space) - 2 (right padding) = Width - 7
            # We use 8 to be safe and consistent with previous layout
            max_text_width = width - 8

            # Wrap text nicely
            wrapped_lines = textwrap.wrap(rec, width=max_text_width)

            if not wrapped_lines:
                continue

            # First line gets the bullet point
            first_line = wrapped_lines[0]
            self._print_alert_row(f"{Colors.colorize(icon, color)} {first_line}", risk_color)

            # Subsequent lines get indentation based on icon width
            # ► is 1 char, ⚠️ is 2 chars (usually). We align to 3 spaces for visual consistency.
            indent = "   " if icon == "⚠️ " else "  "

            for line in wrapped_lines[1:]:
                self._print_alert_row(f"{indent}{line}", risk_color)

        # Bottom Border (└───┘)
        print(Colors.colorize(f"└{'─'*border_len}┘", risk_color))
        print()

    def _console_alert(self, report: ThreatReport):
        """Print alert to console with enhanced UX"""
        # Configuration
        WIDTH = 70
        risk_color = Colors.get_risk_color(report.risk_level)
        risk_symbol = Colors.get_risk_symbol(report.risk_level)

        # Format timestamp
        try:
            dt = datetime.fromisoformat(report.timestamp)
            formatted_time = dt.strftime("%b %d, %Y at %H:%M:%S")
        except ValueError:
            formatted_time = report.timestamp

        self._print_alert_header(report.risk_level, formatted_time, WIDTH, risk_color, risk_symbol)
        self._print_alert_metadata(report, WIDTH, risk_color, formatted_time)
        self._print_threat_score(report.overall_threat_score, report.risk_level, WIDTH, risk_color)
        self._print_analysis_details(report, WIDTH, risk_color)
        self._print_recommendations(report.recommendations, WIDTH, risk_color)

    def _console_clean_report(self, report: ThreatReport):
        """Print clean report to console"""
        # Compact format for clean emails
        score_val = max(0.0, report.overall_threat_score)

        # Calculate risk relative to the low threshold (the "clean" budget)
        threshold = self.config.threat_low
        if threshold <= 0:
            threshold = 30

        percent_of_threshold = min(score_val / threshold, 1.0)

        # Mini bar: 10 chars
        bar_len = 10
        filled = int(percent_of_threshold * bar_len)

        # Bar construction
        fill_char = "■"
        empty_char = "·"

        filled_part = fill_char * filled
        empty_part = empty_char * (bar_len - filled)

        # Color logic
        bar_color = Colors.GREEN
        if percent_of_threshold > 0.6:
            bar_color = Colors.YELLOW

        colored_filled = Colors.colorize(filled_part, bar_color)
        colored_empty = Colors.colorize(empty_part, Colors.GREY)

        visual_bar = f"[{colored_filled}{colored_empty}]"

        # Short timestamp
        try:
            dt = datetime.fromisoformat(report.timestamp)
            time_str = dt.strftime("%H:%M:%S")
        except ValueError:
            time_str = report.timestamp

        # Determine available width based on terminal size
        terminal_width = self._get_terminal_width()

        # Calculate width of fixed parts dynamically
        # Structure: "✓ CLEAN | HH:MM:SS | Score: XX.X [■■···] | From: " + sender + " | " + subject

        sep = Colors.colorize("│", Colors.GREY)

        prefix = f"{Colors.GREEN}✓ CLEAN{Colors.RESET} {sep} {time_str} {sep} Score: {score_val:4.1f} {visual_bar} {sep} From: "
        prefix_len = self._get_visual_length(prefix)

        suffix_sep = f" {sep} "
        suffix_sep_len = self._get_visual_length(suffix_sep)

        # Fixed width is prefix + space for suffix separator
        # We add 1 char buffer
        fixed_width = prefix_len + suffix_sep_len + 1

        available_width = max(20, terminal_width - fixed_width)

        # Allocate width: 35% for sender, 65% for subject
        sender_target = int(available_width * 0.35)
        # Minimum reduced to 8 to fit 80-column terminals better
        sender_width = max(8, sender_target)

        subject_width = available_width - sender_width
        # Ensure subject has at least some space
        subject_width = max(10, subject_width)

        # Sender truncated
        sanitized_sender = self._sanitize_text(report.sender, csv_safe=True)
        sender = self._truncate_text(sanitized_sender, sender_width)

        # Subject truncated
        sanitized_subject = self._sanitize_text(report.subject, csv_safe=True)
        if not sanitized_subject:
            sanitized_subject = "(No Subject)"

        subject = self._truncate_text(sanitized_subject, subject_width)

        # Format:
        # ✓ CLEAN | HH:MM:SS | Score: XX.X [■■···] | From: Sender                       | Subject
        print(
            f"{Colors.GREEN}✓ CLEAN{Colors.RESET} "
            f"{sep} {time_str} "
            f"{sep} Score: {score_val:4.1f} {visual_bar} "
            f"{sep} From: {sender:<{sender_width}} "
            f"{sep} {subject}"
        )

    def _get_terminal_width(self) -> int:
        """Get the current terminal width or default to 80.

        This is wrapped in a try/except so we don't crash in environments where
        shutil.get_terminal_size is unavailable or cannot determine the size.
        In those cases we conservatively fall back to 80 columns.
        """
        try:
            return shutil.get_terminal_size((80, 20)).columns
        except (AttributeError, OSError, ValueError):
            # AttributeError: get_terminal_size might not exist (older/embedded runtimes)
            # OSError/ValueError: terminal size can't be determined in this environment
            return 80
    def _get_visual_length(self, text: str) -> int:
        """Get the character count of text after stripping ANSI color codes."""
        if not text:
            return 0
        return len(ANSI_PATTERN.sub('', text))

    def _truncate_text(self, text: str, width: int) -> str:
        """
        Truncate text to a specified width based on character count.
        Adds '...' if truncated. Assumes input text has no ANSI codes.
        """
        if not text:
            return ""

        # Simple truncation since input (sanitized sender/subject) doesn't have ANSI codes
        if len(text) > width:
            # We need at least 3 chars for '...'
            if width <= 3:
                return "." * width
            return text[:width-3] + "..."
        return text

    def _webhook_alert(self, report: ThreatReport) -> bool:
        """Send alert via webhook.

        Returns True on successful delivery, False on any failure (SSRF block,
        non-200 response, or network error).  All errors are logged here; the
        return value lets ``_dispatch_alert_async`` surface the failure so the
        retry loop in ``_alert_worker`` can attempt redelivery.
        """
        try:
            # SECURITY: Perform SSRF check at request time to mitigate DNS rebinding attacks
            is_safe, err_msg = is_safe_webhook_url(self.config.webhook_url)
            if not is_safe:
                self.logger.error(f"Aborting webhook alert (SSRF prevention): {err_msg}")
                return False

            payload = asdict(report)

            # Redact sensitive info from suspicious URLs if present
            if 'spam_analysis' in payload and 'suspicious_urls' in payload['spam_analysis']:
                urls = payload['spam_analysis']['suspicious_urls']
                if urls:
                    payload['spam_analysis']['suspicious_urls'] = [
                        self._redact_sensitive_url_params(url) for url in urls
                    ]

            response = requests.post(
                self.config.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10,
                allow_redirects=False
            )

            if response.status_code == 200:
                self.logger.info("Webhook alert sent successfully")
                return True
            else:
                self.logger.warning(f"Webhook alert failed: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {self._sanitize_error_message(e)}")
            return False

    def _sanitize_error_message(self, error: Exception) -> str:
        """
        Sanitize exception messages to prevent leaking sensitive URLs/tokens.
        Detects URLs in the error message and redacts them.
        """
        msg = str(error)
        try:
            # Find all URLs in the message
            # Simple regex for http/https URLs to catch full URLs including query params
            urls = URL_PATTERN.findall(msg)

            for url in urls:
                # Clean up trailing punctuation that might have been matched
                clean_url = url.rstrip('.,;:)\'')

                # Apply redaction
                redacted = self._redact_url_secrets(clean_url)

                # If redaction changed anything, update the message
                if redacted != clean_url:
                    msg = msg.replace(clean_url, redacted)

            return msg
        except Exception:
            return "An error occurred (details redacted for security)"

    def _redact_url_secrets(self, url: str) -> str:
        """
        Redact sensitive information from URL (query params and specific paths).
        Handles Slack/Discord webhooks and sensitive query parameters.
        """
        try:
            if not url:
                return ""

            # 1. Redact sensitive query parameters (reusing logic)
            url = self._redact_sensitive_url_params(url)

            parsed = urlparse(url)

            # 2. Redact credentials in authority section
            if parsed.password:
                # Reconstruct URL with redacted password.
                # Use netloc.rpartition to safely separate authority from host, preserving IPv6 brackets.
                _, _, host_part = parsed.netloc.rpartition('@')

                if parsed.username:
                    # Extract the raw username from the netloc to avoid re-encoding ambiguity
                    # parsed.netloc is "user:pass@host", so partition gives us "user:pass"
                    user_pass_part = parsed.netloc.rpartition('@')[0]
                    # Partition gives us "user"
                    username_part = user_pass_part.partition(':')[0]
                    new_netloc = f"{username_part}:[REDACTED]@{host_part}"
                else:
                    # Case: https://:password@host (no username)
                    new_netloc = f":[REDACTED]@{host_part}"

                parsed = parsed._replace(netloc=new_netloc)

            # 3. Redact Slack Webhooks
            # Format: /services/T000/B000/TOKEN
            netloc = parsed.netloc.lower()
            if (not netloc or netloc == "hooks.slack.com" or netloc.endswith(".slack.com")) and parsed.path.startswith("/services/"):
                parts = parsed.path.split('/')
                # parts[0] is empty, parts[1] is 'services'
                # parts[2] is Team ID, parts[3] is Bot ID, parts[4] is Token
                # We redact the token (last part)
                if len(parts) >= 5:
                    parts[-1] = "[REDACTED]"
                    new_path = "/".join(parts)
                    parsed = parsed._replace(path=new_path)
                    return urlunparse(parsed)

            # 4. Redact Discord Webhooks
            # Format: /api/webhooks/ID/TOKEN
            if (not netloc or netloc == "discord.com" or netloc.endswith(".discord.com")) and parsed.path.startswith("/api/webhooks/"):
                parts = parsed.path.split('/')
                # parts[-1] is likely the token
                if len(parts) >= 5:
                    parts[-1] = "[REDACTED]"
                    new_path = "/".join(parts)
                    parsed = parsed._replace(path=new_path)
                    return urlunparse(parsed)

            return urlunparse(parsed)
        except Exception:
            return url

    def _redact_sensitive_url_params(self, url: str) -> str:
        """
        Redact sensitive query parameters from URL.
        Prevents leaking credentials or tokens in logs/alerts.
        """
        try:
            if not url:
                return ""

            parsed = urlparse(url)
            # keep_blank_values=True ensures we don't drop empty params
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            sensitive_keys = {
                'password', 'token', 'secret', 'key', 'apikey', 'api_key',
                'access_token', 'auth', 'authorization', 'sig', 'signature'
            }

            changed = False
            for key in query_params:
                if key.lower() in sensitive_keys:
                    query_params[key] = ['[REDACTED]']
                    changed = True

            if changed:
                # doseq=True handles lists of values correctly
                new_query = urlencode(query_params, doseq=True)
                parsed = parsed._replace(query=new_query)
                return urlunparse(parsed)
            return url
        except Exception:
            # If parsing fails, return original to avoid losing data,
            # but rely on other sanitization layers if any.
            return url

    def _sanitize_text(self, text: str, csv_safe: bool = False) -> str:
        """
        Sanitize text for safe console output.
        Removes control characters, BiDi overrides, and normalizes whitespace.

        Args:
            text: Input text
            csv_safe: If True, applies CSV/Formula injection prevention
        """
        if not text:
            return ""

        # Replace newlines and tabs with spaces
        sanitized = text.translate(str.maketrans('\n\r\t', '   '))

        # Remove non-printable characters (including BiDi overrides, control chars, etc.)
        # Only keep characters that are printable or separators (Zs)
        sanitized = ''.join(
            c for c in sanitized
            if c.isprintable() or unicodedata.category(c) == 'Zs'
        )

        if csv_safe:
            # Prevent Formula/CSV Injection for console logs that might be exported
            sanitized = sanitize_for_csv(sanitized)

        return sanitized

    def _sanitize_for_slack(self, text: str) -> str:
        """
        Sanitize text for Slack to prevent injection and spoofing.
        Escapes &, <, > and sanitizes control characters.
        """
        if not text:
            return ""

        # First sanitize control characters using the existing method
        # We do NOT use csv_safe=True here to avoid messing up Slack formatting
        text = self._sanitize_text(text, csv_safe=False)

        # Escape Slack special characters
        # Reference: https://api.slack.com/reference/surfaces/formatting#escaping
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def _create_slack_field(self, title: str, analysis_dict: Dict, indicator: str) -> Dict:
        """Helper to create a standard Slack field dictionary with risk emojis"""
        level = analysis_dict.get('risk_level', 'unknown')
        score = analysis_dict.get('score', 0)
        symbol = Colors.get_risk_symbol(level)

        value = f"{symbol} {level.upper()} ({score:.2f})"
        if indicator:
            value += f"{indicator}"

        return {
            "title": title,
            "value": value,
            "short": True
        }

    def _slack_alert(self, report: ThreatReport) -> bool:
        """Send alert to Slack.

        Returns True on successful delivery, False on any failure (SSRF block,
        non-200 response, or network error).  All errors are logged here; the
        return value lets ``_dispatch_alert_async`` surface the failure so the
        retry loop in ``_alert_worker`` can attempt redelivery.
        """
        try:
            # SECURITY: Perform SSRF check at request time to mitigate DNS rebinding attacks
            is_safe, err_msg = is_safe_webhook_url(self.config.slack_webhook)
            if not is_safe:
                self.logger.error(f"Aborting Slack alert (SSRF prevention): {err_msg}")
                return False

            # Format Slack message
            color = {
                "low": "#36a64f",
                "medium": "#ff9900",
                "high": "#ff0000"
            }.get(report.risk_level, "#808080")
            fields = [
                {
                    "title": "Subject",
                    "value": self._sanitize_for_slack(report.subject),
                    "short": False
                },
                {
                    "title": "From",
                    "value": self._sanitize_for_slack(report.sender),
                    "short": True
                },
                {
                    "title": "Overall Threat Score",
                    "value": f"{report.overall_threat_score:.2f}",
                    "short": True
                }
            ]

            # Add analysis breakdown using helper method
            # Spam
            spam_data = report.spam_analysis or {}
            spam_ind = ""
            if spam_data.get('indicators'):
                spam_ind = f" - {spam_data['indicators'][0]}"
            elif spam_data.get('suspicious_urls'):
                spam_ind = " - Suspicious URLs"

            fields.append(self._create_slack_field(
                "📧 Spam Analysis",
                spam_data,
                spam_ind
            ))

            # NLP
            nlp_data = report.nlp_analysis or {}
            nlp_ind = ""
            if nlp_data.get('social_engineering_indicators'):
                nlp_ind = f" - {nlp_data['social_engineering_indicators'][0]}"
            elif nlp_data.get('authority_impersonation'):
                nlp_ind = f" - {nlp_data['authority_impersonation'][0]}"

            fields.append(self._create_slack_field(
                "🧠 NLP Analysis",
                nlp_data,
                nlp_ind
            ))

            # Media
            media_data = report.media_analysis or {}
            media_ind = ""
            if media_data.get('file_type_warnings'):
                media_ind = f" - {media_data['file_type_warnings'][0]}"
            elif media_data.get('potential_deepfakes'):
                media_ind = " - Deepfake Detected"

            fields.append(self._create_slack_field(
                "📎 Media Analysis",
                media_data,
                media_ind
            ))

            # Top Recommendation
            fields.append({
                "title": "Top Recommendation",
                "value": report.recommendations[0] if report.recommendations else "Review email",
                "short": False
            })

            attachments = [{
                "color": color,
                "title": (
                    f"🚨 Security Alert - {report.risk_level.upper()} Risk"
                ),
                "fields": fields,
                "footer": "Email Security Pipeline",
                "ts": int(datetime.now().timestamp())
            }]

            payload = {
                "text": "New email security threat detected",
                "attachments": attachments
            }

            response = requests.post(
                self.config.slack_webhook,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10,
                allow_redirects=False
            )

            if response.status_code == 200:
                self.logger.info("Slack alert sent successfully")
                return True
            else:
                self.logger.warning(f"Slack alert failed: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {self._sanitize_error_message(e)}")
            return False

    @staticmethod
    def _generate_recommendations(
        spam_result: SpamAnalysisResult,
        nlp_result: NLPAnalysisResult,
        media_result: MediaAnalysisResult
    ) -> List[str]:
        """Generate actionable recommendations based on threat analysis results."""
        recommendations = []

        # High-risk recommendations
        if spam_result.risk_level == "high":
            recommendations.append("⚠️ HIGH RISK: Move to spam folder immediately")

        if nlp_result.social_engineering_indicators:
            recommendations.append("🎣 Potential phishing: Do not click links or provide credentials")

        if media_result.file_type_warnings:
            recommendations.append("📎 Dangerous attachment detected: Do not open attachments")

        # Medium-risk recommendations
        if spam_result.suspicious_urls:
            recommendations.append("🔗 Suspicious URLs detected: Verify links before clicking")

        if nlp_result.authority_impersonation:
            recommendations.append("👤 Authority impersonation suspected: Verify sender identity")

        if nlp_result.urgency_markers:
            recommendations.append("⏰ Urgency tactics detected: Take time to verify before acting")

        # General recommendations
        if not recommendations:
            recommendations.append(AlertSystem.DEFAULT_CLEAN_RECOMMENDATION)

        return recommendations


def generate_threat_report(
    email_data: EmailData,
    spam_result: SpamAnalysisResult,
    nlp_result: NLPAnalysisResult,
    media_result: MediaAnalysisResult
) -> ThreatReport:
    """
    Generate comprehensive threat report

    Args:
        email_data: Email data
        spam_result: Spam analysis result
        nlp_result: NLP analysis result
        media_result: Media analysis result

    Returns:
        ThreatReport
    """
    # Calculate overall threat score
    overall_score = (
        spam_result.score +
        nlp_result.threat_score +
        media_result.threat_score
    )

    # Determine overall risk level
    if spam_result.risk_level == "high" or nlp_result.risk_level == "high" or media_result.risk_level == "high":
        risk_level = "high"
    elif spam_result.risk_level == "medium" or nlp_result.risk_level == "medium" or media_result.risk_level == "medium":
        risk_level = "medium"
    else:
        risk_level = "low"

    # Generate recommendations
    recommendations = AlertSystem._generate_recommendations(spam_result, nlp_result, media_result)

    return ThreatReport(
        email_id=email_data.message_id,
        subject=email_data.subject,
        sender=email_data.sender,
        recipient=email_data.recipient,
        date=email_data.date.isoformat(),
        overall_threat_score=overall_score,
        risk_level=risk_level,
        spam_analysis={
            'score': spam_result.score,
            'risk_level': spam_result.risk_level,
            'indicators': spam_result.indicators,
            'suspicious_urls': spam_result.suspicious_urls,
            'header_issues': spam_result.header_issues
        },
        nlp_analysis={
            'score': nlp_result.threat_score,
            'risk_level': nlp_result.risk_level,
            'social_engineering_indicators': nlp_result.social_engineering_indicators,
            'urgency_markers': nlp_result.urgency_markers,
            'authority_impersonation': nlp_result.authority_impersonation,
            'psychological_triggers': nlp_result.psychological_triggers
        },
        media_analysis={
            'score': media_result.threat_score,
            'risk_level': media_result.risk_level,
            'suspicious_attachments': media_result.suspicious_attachments,
            'file_type_warnings': media_result.file_type_warnings,
            'size_anomalies': media_result.size_anomalies,
            'potential_deepfakes': media_result.potential_deepfakes
        },
        recommendations=recommendations,
        timestamp=datetime.now().isoformat()
    )
