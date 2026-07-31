"""
Alert and Response System
Handles threat notifications and alerting across multiple channels.
"""

import asyncio
import logging
import threading
from typing import Dict, List, Optional

import requests

from ..utils.security_validators import is_safe_webhook_url
from .alert_recommendations import (
    DEFAULT_CLEAN_RECOMMENDATION,
    RECOMMENDATION_PREFIXES,
    RECOMMENDATION_PREFIXES_TUPLE,
    RED_KEYWORDS_PATTERN,
    YELLOW_KEYWORDS_PATTERN,
    generate_recommendations,
)
from .alert_report import RenderConfig, ThreatReport, generate_threat_report
from .media_analyzer import MediaAnalysisResult
from .nlp_analyzer import NLPAnalysisResult
from .spam_analyzer import SpamAnalysisResult
from . import alert_channels
from . import alert_console


class AlertSystem:
    """Manages alerts and notifications."""

    # Common prefixes for recommendations to strip during display to prevent duplication
    RECOMMENDATION_PREFIXES = RECOMMENDATION_PREFIXES

    # Pre-allocated tuple for fast C-level execution of startswith()
    RECOMMENDATION_PREFIXES_TUPLE = RECOMMENDATION_PREFIXES_TUPLE

    # Compiled regex patterns for fast substring keyword checks in recommendations
    # Use re.compile directly since we are passing a single regex string, not a list
    RED_KEYWORDS_PATTERN = RED_KEYWORDS_PATTERN
    YELLOW_KEYWORDS_PATTERN = YELLOW_KEYWORDS_PATTERN


    # Maximum number of items shown per section in the console threat report.
    # Helps keep the output readable; lists may be truncated in the console view.
    MAX_SPAM_INDICATORS_DISPLAY = 5
    MAX_HEADER_ISSUES_DISPLAY = 5
    MAX_NLP_INDICATORS_DISPLAY = 3
    MAX_MEDIA_WARNINGS_DISPLAY = 3
    MAX_URLS_DISPLAY = 3

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
    DEFAULT_CLEAN_RECOMMENDATION = DEFAULT_CLEAN_RECOMMENDATION

    def __init__(self, config):
        """
        Initialize alert system.

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
        if self._alert_queue is None:
            raise RuntimeError("self._alert_queue must be set before event loop starts")

        while True:
            report = await self._alert_queue.get()
            if report is None:
                # Sentinel received – drain complete, stop worker.
                self._alert_queue.task_done()
                break

            await self._process_single_alert_with_retry(report)
            self._alert_queue.task_done()

    async def _process_single_alert_with_retry(self, report: ThreatReport) -> None:
        """Process a single alert report with exponential backoff and retries."""
        dispatched = False
        for attempt in range(self.MAX_DISPATCH_RETRIES):
            try:
                await asyncio.wait_for(self._dispatch_alert_async(report), timeout=10.0)
                dispatched = True
                break
            except asyncio.TimeoutError:
                self.logger.error(
                    "Alert dispatch timed out for email %s (attempt %d/%d)",
                    report.email_id,
                    attempt + 1,
                    self.MAX_DISPATCH_RETRIES,
                )
            except Exception as exc:
                self.logger.error(
                    "Alert dispatch failed for email %s (attempt %d/%d): %s",
                    report.email_id,
                    attempt + 1,
                    self.MAX_DISPATCH_RETRIES,
                    exc,
                )

            if attempt < self.MAX_DISPATCH_RETRIES - 1:
                # Exponential backoff: 1 s → 2 s → 4 s
                await asyncio.sleep(2**attempt)

        if not dispatched:
            self.logger.error(
                "Alert permanently failed for email %s after %d attempts",
                report.email_id,
                self.MAX_DISPATCH_RETRIES,
            )

    async def _dispatch_alert_async(self, report: ThreatReport) -> None:
        """Dispatch a single alert through all configured channels (async wrapper).

        Each synchronous I/O call (_webhook_alert, _slack_alert) is offloaded to
        the default executor so the event loop is never blocked.  Raises
        RuntimeError if any configured channel fails so the caller (_alert_worker)
        can apply retry logic.
        """
        # Console output is fast (no I/O); run directly in event loop thread.
        if self.config.console:
            self._console_alert(report)

        failed_channels = await self._dispatch_external_alerts_async(report)

        if failed_channels:
            raise RuntimeError(
                f"Alert dispatch failed for channels: {', '.join(failed_channels)}"
            )

    async def _dispatch_external_alerts_async(self, report: ThreatReport) -> List[str]:
        """Helper to run webhook and slack alerts in parallel and collect failed channels."""
        loop = asyncio.get_running_loop()
        tasks = []
        channel_names = []

        if self.config.webhook_enabled and self.config.webhook_url:
            tasks.append(loop.run_in_executor(None, self._webhook_alert, report))
            channel_names.append("webhook")

        if self.config.slack_enabled and self.config.slack_webhook:
            tasks.append(loop.run_in_executor(None, self._slack_alert, report))
            channel_names.append("slack")

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return self._process_dispatch_results(channel_names, results)

    def _process_dispatch_results(
        self, channel_names: List[str], results: List
    ) -> List[str]:
        """Process results from gather and return a list of failed channel names."""
        failed = []
        for channel, result in zip(channel_names, results):
            if isinstance(result, Exception):
                self.logger.error(
                    "Alert dispatch failed unexpectedly for %s: %s", channel, result
                )
                failed.append(channel)
            elif not result:
                failed.append(channel)
        return failed

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
        # Alert when any analysis layer flagged medium/high risk, OR when the
        # combined score meets THREAT_LOW. Layer risk uses per-analyser
        # thresholds (e.g. SPAM_THRESHOLD=5 → high at score 10), while
        # overall_threat_score is a sum that can stay below THREAT_LOW=30 even
        # when risk_level is already "high". Gating on score alone silently
        # dropped flagged/suspicious notifications.
        risk = (threat_report.risk_level or "").lower()
        score_below_floor = threat_report.overall_threat_score < self.config.threat_low
        if risk not in ("medium", "high") and score_below_floor:
            self.logger.debug(
                "Threat too low to alert: score=%s risk=%s",
                threat_report.overall_threat_score,
                threat_report.risk_level,
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
                self.logger.debug(
                    "Alert enqueue future was cancelled (likely during shutdown)."
                )
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

    def _safe_console_url(self, url: str) -> str:
        """Return a URL safe for console output with tokens redacted."""
        return alert_console.safe_console_url(url)

    def _get_terminal_width(self) -> int:
        """Get the current terminal width or default to 80."""
        return alert_console.get_terminal_width()

    def _get_visual_length(self, text: str) -> int:
        """Get the character count of text after stripping ANSI color codes."""
        return alert_console.get_visual_length(text)

    def _truncate_text(self, text: str, width: int) -> str:
        """Truncate text to a specified width based on character count."""
        return alert_console.truncate_text(text, width)

    def _console_alert(self, report: ThreatReport):
        """Print alert to console with enhanced UX."""
        alert_console.render_alert(
            report,
            limits={
                "MAX_SPAM_INDICATORS_DISPLAY": self.MAX_SPAM_INDICATORS_DISPLAY,
                "MAX_HEADER_ISSUES_DISPLAY": self.MAX_HEADER_ISSUES_DISPLAY,
                "MAX_NLP_INDICATORS_DISPLAY": self.MAX_NLP_INDICATORS_DISPLAY,
                "MAX_MEDIA_WARNINGS_DISPLAY": self.MAX_MEDIA_WARNINGS_DISPLAY,
                "MAX_URLS_DISPLAY": self.MAX_URLS_DISPLAY,
            },
        )

    def _console_clean_report(self, report: ThreatReport):
        """Print clean report to console."""
        alert_console.render_clean_report(
            report,
            self.config.threat_low,
            self._get_terminal_width(),
        )

    def _sanitize_text(self, text: str, csv_safe: bool = False) -> str:
        """Sanitize text for safe console output."""
        return alert_channels.sanitize_text(text, csv_safe)

    def _sanitize_for_slack(self, text: str) -> str:
        """Sanitize text for Slack to prevent injection and spoofing."""
        return alert_channels.sanitize_for_slack(text)

    def _sanitize_error_message(self, error: Exception) -> str:
        """Sanitize exception messages to prevent leaking sensitive URLs/tokens."""
        return alert_channels.sanitize_error_message(str(error))

    def _redact_url_secrets(self, url: str) -> str:
        """Redact sensitive information from URL (query params and specific paths)."""
        return alert_channels.redact_url_secrets(url)

    def _redact_sensitive_url_params(self, url: str) -> str:
        """Redact sensitive query parameters from URL."""
        return alert_channels.redact_sensitive_url_params(url)

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
                self.logger.error(
                    f"Aborting webhook alert (SSRF prevention): {err_msg}"
                )
                return False

            response = requests.post(
                self.config.webhook_url,
                json=alert_channels.build_webhook_payload(report),
                headers={"Content-Type": "application/json"},
                timeout=10,
                allow_redirects=False,
                verify=True,
            )

            if response.status_code == 200:
                self.logger.info("Webhook alert sent successfully")
                return True
            else:
                self.logger.warning(f"Webhook alert failed: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(
                f"Failed to send webhook alert: {self._sanitize_error_message(e)}"
            )
            return False

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

            response = requests.post(
                self.config.slack_webhook,
                json=alert_channels.build_slack_payload(report),
                headers={"Content-Type": "application/json"},
                timeout=10,
                allow_redirects=False,
                verify=True,
            )

            if response.status_code == 200:
                self.logger.info("Slack alert sent successfully")
                return True
            else:
                self.logger.warning(f"Slack alert failed: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(
                f"Failed to send Slack alert: {self._sanitize_error_message(e)}"
            )
            return False

    @staticmethod
    def _generate_recommendations(
        spam_result: SpamAnalysisResult,
        nlp_result: NLPAnalysisResult,
        media_result: MediaAnalysisResult,
    ) -> List[str]:
        """Generate actionable recommendations based on threat analysis results."""
        return generate_recommendations(spam_result, nlp_result, media_result)
