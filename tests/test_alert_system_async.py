"""
Async Alert Dispatch Tests

Validates that the async alert worker:
- Dispatches alerts without blocking the caller (fire-and-forget)
- Preserves alert ordering via the asyncio.Queue
- Times out alerts that take too long (10 s cap)
- Retries failed dispatches with exponential backoff
- Loses zero alerts during graceful shutdown
- Falls back to synchronous dispatch when the worker is not running
"""

import asyncio
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime

from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(*, console=False, webhook=False, slack=False, threat_low=10):
    """Build a minimal AlertConfig mock."""
    cfg = MagicMock(spec=AlertConfig)
    cfg.console = console
    cfg.webhook_enabled = webhook
    cfg.webhook_url = "https://example.com/webhook" if webhook else ""
    cfg.slack_enabled = slack
    cfg.slack_webhook = "https://hooks.slack.com/services/TEST" if slack else ""
    cfg.threat_low = threat_low
    cfg.threat_medium = 50
    cfg.threat_high = 80
    return cfg


def _make_report(email_id="test-001", score=85.0, risk_level="high"):
    """Build a minimal ThreatReport."""
    return ThreatReport(
        email_id=email_id,
        subject="Test Subject",
        sender="attacker@evil.com",
        recipient="victim@example.com",
        date=datetime.now().isoformat(),
        overall_threat_score=score,
        risk_level=risk_level,
        spam_analysis={},
        nlp_analysis={},
        media_analysis={},
        recommendations=[],
        timestamp=datetime.now().isoformat(),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAlertWorkerLifecycle(unittest.TestCase):
    """Test worker start / stop lifecycle."""

    def test_start_worker_creates_background_thread(self):
        """
        PATTERN RECOGNITION: The worker runs in a dedicated daemon thread so the
        main pipeline is never blocked waiting for a slow webhook endpoint.
        """
        system = AlertSystem(_make_config())
        self.assertIsNone(system._worker_thread)

        system.start_worker()
        try:
            self.assertIsNotNone(system._worker_thread)
            self.assertTrue(system._worker_thread.is_alive())
            self.assertIsNotNone(system._loop)
            self.assertIsNotNone(system._alert_queue)
        finally:
            system.stop_worker()

    def test_start_worker_idempotent(self):
        """Calling start_worker() twice must not spawn a second thread."""
        system = AlertSystem(_make_config())
        system.start_worker()
        try:
            first_thread = system._worker_thread
            system.start_worker()
            self.assertIs(system._worker_thread, first_thread)
        finally:
            system.stop_worker()

    def test_stop_worker_joins_thread(self):
        """stop_worker() must join the worker thread (thread becomes not-alive)."""
        system = AlertSystem(_make_config())
        system.start_worker()
        thread = system._worker_thread

        system.stop_worker()

        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    def test_stop_worker_without_start_is_safe(self):
        """stop_worker() must be a no-op if the worker was never started."""
        system = AlertSystem(_make_config())
        # Should not raise
        system.stop_worker()


class TestAsyncAlertDispatch(unittest.TestCase):
    """Test that send_alert() enqueues asynchronously when worker is running."""

    def _wait_for_queue_drain(self, system: AlertSystem, timeout: float = 5.0) -> None:
        """Block until all queued alerts have been processed.

        Uses ``asyncio.Queue.join()`` scheduled on the worker's own event loop
        so the completion signal is issued by the worker coroutine itself (via
        ``task_done()``), which is fully thread-safe and avoids the data-race
        that arises from calling ``queue.empty()`` across threads.
        """
        loop = system._loop
        if loop is None or loop.is_closed():
            return
        queue = system._alert_queue
        if queue is None:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(queue.join(), loop)
            fut.result(timeout=timeout)
        except Exception:
            pass

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_send_alert_returns_immediately(self, mock_safe, mock_post):
        """
        SECURITY STORY: The pipeline should never be blocked for 5-8 s waiting
        for a slow webhook.  We verify that send_alert() returns in < 200 ms even
        when the actual HTTP call takes 1 s.
        """
        mock_safe.return_value = (True, "")
        # Simulate a slow webhook (1 second delay)
        mock_post.side_effect = lambda *a, **kw: (time.sleep(1), MagicMock(status_code=200))[1]

        system = AlertSystem(_make_config(webhook=True))
        system.start_worker()
        try:
            start = time.monotonic()
            system.send_alert(_make_report())
            elapsed = time.monotonic() - start

            # Fire-and-forget: must return in well under 200 ms
            self.assertLess(elapsed, 0.2, "send_alert() blocked the caller")
        finally:
            system.stop_worker()

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_alerts_processed_after_queue(self, mock_safe, mock_post):
        """Alerts queued via send_alert() must eventually be dispatched."""
        mock_safe.return_value = (True, "")
        mock_post.return_value = MagicMock(status_code=200)

        system = AlertSystem(_make_config(webhook=True))
        system.start_worker()
        try:
            system.send_alert(_make_report(email_id="abc"))
            self._wait_for_queue_drain(system)
            # The worker should have called requests.post at least once
            self.assertTrue(mock_post.called)
        finally:
            system.stop_worker()

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_alert_ordering_preserved(self, mock_safe, mock_post):
        """
        INDUSTRY CONTEXT: asyncio.Queue is FIFO, so alerts must be dispatched in
        the order they were enqueued.  This matters when replaying alerts to an
        audit log.
        """
        mock_safe.return_value = (True, "")
        dispatched_ids = []

        def capture_call(*args, **kwargs):
            payload = kwargs.get("json", {})
            dispatched_ids.append(payload.get("email_id"))
            return MagicMock(status_code=200)

        mock_post.side_effect = capture_call

        system = AlertSystem(_make_config(webhook=True))
        system.start_worker()
        try:
            for i in range(5):
                system.send_alert(_make_report(email_id=f"email-{i}"))
            self._wait_for_queue_drain(system, timeout=10.0)
        finally:
            system.stop_worker()

        # All five alerts must have been dispatched in submission order
        self.assertEqual(dispatched_ids, [f"email-{i}" for i in range(5)])


class TestAlertWorkerTimeout(unittest.TestCase):
    """Test that individual alert dispatch is capped at 10 s."""

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_timeout_does_not_block_queue(self, mock_safe, mock_post):
        """
        SECURITY STORY: A single slow/hanging webhook must not block all
        subsequent alerts.  The 10 s timeout ensures the queue keeps draining.

        This test simulates a true timeout at the asyncio.wait_for layer:
        - The first call to wait_for raises TimeoutError, representing a
          slow/hanging webhook dispatch that hits the 10 s cap.
        - Subsequent calls behave normally so we can verify that the second
          alert is still dispatched.
        """
        mock_safe.return_value = (True, "")

        fast_called = threading.Event()

        def track_fast_post(*args, **kwargs):
            """
            Side effect for requests.post that simply records when the 'fast'
            alert is dispatched. We no longer raise here; the timeout is
            simulated via asyncio.wait_for so the 'slow' alert should never
            reach this function.
            """
            payload = kwargs.get("json", {})
            if payload.get("email_id") == "fast":
                fast_called.set()
            return MagicMock(status_code=200)

        mock_post.side_effect = track_fast_post

        # Patch asyncio.wait_for so the first dispatch times out and subsequent
        # ones complete normally. This directly exercises the 10 s timeout cap
        # without introducing real-time delays into the test suite.
        timeout_triggered = {"value": False}

        async def timeout_once(coro, timeout):
            # First call simulates a timeout of the slow/hanging alert.
            # Close the coroutine explicitly to suppress the "coroutine was
            # never awaited" RuntimeWarning that would otherwise be emitted.
            if not timeout_triggered["value"]:
                timeout_triggered["value"] = True
                coro.close()
                raise asyncio.TimeoutError()
            # Subsequent calls behave as normal wait_for
            return await coro

        system = AlertSystem(_make_config(webhook=True))
        with patch("asyncio.wait_for", new=timeout_once):
            system.start_worker()
            try:
                system.send_alert(_make_report(email_id="slow"))
                system.send_alert(_make_report(email_id="fast"))
                # Fast alert must still be dispatched even after the slow one
                # has timed out at the wait_for layer.
                self.assertTrue(
                    fast_called.wait(timeout=10),
                    "Fast alert was never dispatched",
                )
            finally:
                system.stop_worker()


class TestAlertWorkerRetry(unittest.TestCase):
    """Test exponential-backoff retry for failed dispatches."""

    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_retry_on_failure_then_success(self, mock_safe):
        """
        PATTERN RECOGNITION: Fire-and-forget doesn't mean fire-and-forget-about-
        errors.  Transient network failures should be retried before giving up.

        We patch _webhook_alert (not requests.post) so exceptions propagate up
        through _dispatch_alert_async to the retry loop in _alert_worker.
        The existing _webhook_alert already catches requests.post exceptions, so
        the retry must be triggered by failures at the channel-method boundary.
        """
        mock_safe.return_value = (True, "")
        success_event = threading.Event()

        call_count = [0]

        def flaky_webhook(report):
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("Transient error")
            success_event.set()

        async def instant_sleep(_delay):
            """Skip actual backoff delays in tests."""
            pass  # no-op: avoids real waits during testing

        system = AlertSystem(_make_config(webhook=True))
        with patch("asyncio.sleep", new=instant_sleep):
            system.start_worker()
            try:
                with patch.object(system, "_webhook_alert", side_effect=flaky_webhook):
                    system.send_alert(_make_report())
                    # Allow time for up to MAX_DISPATCH_RETRIES attempts
                    self.assertTrue(
                        success_event.wait(timeout=10),
                        "Alert was never successfully delivered after retries",
                    )
                    self.assertEqual(call_count[0], 3)
            finally:
                system.stop_worker()

    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_permanent_failure_logged_after_max_retries(self, mock_safe):
        """After MAX_DISPATCH_RETRIES exhausted, all retries are attempted and the worker continues.

        We patch _webhook_alert directly (not requests.post) so failures
        propagate to _dispatch_alert_async and the retry loop actually counts
        them.  _webhook_alert normally catches requests.post exceptions, so
        patching at the HTTP layer would have no visible effect on the retries.
        """
        mock_safe.return_value = (True, "")
        call_count = [0]

        def always_fail(report):
            call_count[0] += 1
            raise RuntimeError("Permanent failure")

        async def instant_sleep(_delay):
            pass  # no-op: avoids real waits during testing

        system = AlertSystem(_make_config(webhook=True))
        # Both patches must wrap start_worker AND stop_worker so they remain
        # active while the worker processes the alert in the background.
        with patch("asyncio.sleep", new=instant_sleep):
            with patch.object(system, "_webhook_alert", side_effect=always_fail):
                system.start_worker()
                try:
                    system.send_alert(_make_report(email_id="fail-1"))
                    # stop_worker() drains the queue; by the time it returns all
                    # MAX_DISPATCH_RETRIES attempts have completed.
                finally:
                    system.stop_worker()

        # Verify that all retry attempts were made (not short-circuited).
        self.assertEqual(
            call_count[0],
            AlertSystem.MAX_DISPATCH_RETRIES,
            f"Expected {AlertSystem.MAX_DISPATCH_RETRIES} retry attempts, got {call_count[0]}",
        )


class TestZeroAlertsLostOnShutdown(unittest.TestCase):
    """Verify that stop_worker() flushes all queued alerts before returning."""

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_all_queued_alerts_dispatched_on_shutdown(self, mock_safe, mock_post):
        """
        MAINTENANCE WISDOM: Security teams rely on every alert being delivered.
        Dropping alerts during shutdown would create silent gaps in audit logs.
        """
        mock_safe.return_value = (True, "")
        dispatched = []

        def capture(*args, **kwargs):
            dispatched.append(kwargs.get("json", {}).get("email_id"))
            return MagicMock(status_code=200)

        mock_post.side_effect = capture

        system = AlertSystem(_make_config(webhook=True))
        system.start_worker()

        n = 10
        for i in range(n):
            system.send_alert(_make_report(email_id=f"shutdown-{i}"))

        # stop_worker() must flush the queue before returning
        system.stop_worker()

        self.assertEqual(len(dispatched), n, f"Expected {n} alerts, got {len(dispatched)}")


class TestSyncFallback(unittest.TestCase):
    """Test synchronous dispatch when worker has not been started."""

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_sync_dispatch_when_worker_not_started(self, mock_safe, mock_post):
        """
        INDUSTRY CONTEXT: In test suites and scripts the worker is often not
        started.  Falling back to sync ensures no alerts are silently swallowed.
        """
        mock_safe.return_value = (True, "")
        mock_post.return_value = MagicMock(status_code=200)

        system = AlertSystem(_make_config(webhook=True))
        # Worker NOT started deliberately
        system.send_alert(_make_report())

        # Must have dispatched synchronously
        self.assertTrue(mock_post.called)

    def test_below_threshold_does_not_dispatch(self):
        """Alerts below the threat_low threshold must never be dispatched."""
        system = AlertSystem(_make_config(webhook=True, threat_low=50))
        with patch.object(system, "_dispatch_alert_sync") as mock_sync:
            system.send_alert(_make_report(score=5.0))  # Below threshold
            mock_sync.assert_not_called()


class TestOnEnqueueDone(unittest.TestCase):
    """Unit tests for AlertSystem._on_enqueue_done Future callback.

    The callback is synchronous and purely inspects the Future; no real asyncio
    event loop or threads are needed.  All branches are exercised via MagicMock
    futures with controlled side-effects on fut.exception().
    """

    def _make_system(self) -> AlertSystem:
        return AlertSystem(_make_config())

    def test_branch_a_cancelled_error_no_error_logged(self):
        """Branch A — fut.exception() raises CancelledError: no error is logged.

        SECURITY STORY: During shutdown the worker loop is cancelled; this should
        never pollute the logs with spurious error messages that mask real alerts.
        """
        system = self._make_system()
        system.logger = MagicMock()
        fut = MagicMock()
        fut.exception.side_effect = asyncio.CancelledError()

        system._on_enqueue_done(fut)

        system.logger.error.assert_not_called()
        # Debug log IS emitted when DEBUG level is enabled (MagicMock isEnabledFor is truthy)
        system.logger.debug.assert_called_once()

    def test_branch_b_unexpected_exception_logs_error(self):
        """Branch B — fut.exception() itself raises unexpectedly: logs exactly one error.

        MAINTENANCE WISDOM: If the Future framework ever changes behaviour, we want
        a visible diagnostic rather than a silent failure.
        """
        system = self._make_system()
        system.logger = MagicMock()
        fut = MagicMock()
        fut.exception.side_effect = RuntimeError("internal error")

        system._on_enqueue_done(fut)

        # First, ensure exactly one error log entry was emitted.
        system.logger.error.assert_called_once()
        # Then, verify the diagnostic content and that the original exception
        # raised by fut.exception() is passed through to the logger. This pins
        # the Branch B behaviour rather than just the fact that "something" was logged.
        error_args, error_kwargs = system.logger.error.call_args
        # Defensive: we expect the first positional arg to be the log message
        self.assertIsInstance(error_args[0], str)
        self.assertTrue(
            error_args[0].startswith("Unexpected error while inspecting enqueue future"),
            msg=f"Unexpected error log message: {error_args[0]!r}",
        )
        # The runtime error that fut.exception() raised should be surfaced to logging.
        # Common pattern: logger.error(message, exc_info=err)
        self.assertIn("exc_info", error_kwargs)
        self.assertIs(error_kwargs["exc_info"], fut.exception.side_effect)

    def test_branch_c_queue_full_logs_dropped_alert(self):
        """Branch C — QueueFull: logs error with 'queue is full' and 'alert dropped'.

        SECURITY STORY: This is the ONLY observability point when an alert is
        silently dropped because the queue is saturated.  A regression here means
        operators would never know alerts were lost.
        """
        system = self._make_system()
        system.logger = MagicMock()
        fut = MagicMock()
        fut.exception.return_value = asyncio.QueueFull()

        system._on_enqueue_done(fut)

        system.logger.error.assert_called_once()
        # The format string is the first positional arg; it must contain both
        # sentinel phrases so the log is recognisable in production monitoring.
        error_format = system.logger.error.call_args[0][0]
        self.assertIn("queue is full", error_format.lower())
        self.assertIn("alert dropped", error_format.lower())

    def test_branch_d_generic_failure_logs_error(self):
        """Branch D — generic enqueue exception: logs error with correct message and exception."""
        system = self._make_system()
        system.logger = MagicMock()
        fut = MagicMock()
        # Use a named exception instance so we can assert identity, not just equality.
        enqueue_exc = ValueError("bad payload")
        fut.exception.return_value = enqueue_exc

        system._on_enqueue_done(fut)

        # Ensure exactly one error log was emitted for this failure.
        system.logger.error.assert_called_once()
        error_args = system.logger.error.call_args[0]
        # Expect a standard logging call: logger.error("Failed to enqueue alert: %s", exc)
        self.assertGreaterEqual(
            len(error_args),
            2,
            "logger.error should be called with a format string and the exception object",
        )
        self.assertEqual("Failed to enqueue alert: %s", error_args[0])
        # The exception passed to logger.error must be the same object returned by fut.exception()
        self.assertIs(enqueue_exc, error_args[1])

    def test_happy_path_no_exception_nothing_logged(self):
        """Happy path — fut.exception() returns None: nothing is logged at all."""
        system = self._make_system()
        system.logger = MagicMock()
        fut = MagicMock()
        fut.exception.return_value = None

        system._on_enqueue_done(fut)

        system.logger.error.assert_not_called()
        system.logger.debug.assert_not_called()


if __name__ == "__main__":
    unittest.main()
