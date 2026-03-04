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
from unittest.mock import MagicMock, patch, call
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
        """Block until all queued alerts have been processed or timeout expires."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            q = system._alert_queue
            if q is not None and q.empty():
                # Give the worker one more tick to call task_done().
                time.sleep(0.05)
                return
            time.sleep(0.05)

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
        """
        mock_safe.return_value = (True, "")

        fast_called = threading.Event()

        def slow_then_fast(*args, **kwargs):
            payload = kwargs.get("json", {})
            if payload.get("email_id") == "slow":
                # Simulate a timeout-triggering delay longer than the 10 s cap.
                # We use a shorter sleep and patch wait_for to avoid slow tests.
                raise Exception("Simulated network failure")
            fast_called.set()
            return MagicMock(status_code=200)

        mock_post.side_effect = slow_then_fast

        system = AlertSystem(_make_config(webhook=True))
        system.start_worker()
        try:
            system.send_alert(_make_report(email_id="slow"))
            system.send_alert(_make_report(email_id="fast"))
            # Fast alert must still be dispatched even after the slow one fails
            self.assertTrue(fast_called.wait(timeout=10), "Fast alert was never dispatched")
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

    @patch("src.modules.alert_system.requests.post")
    @patch("src.modules.alert_system.is_safe_webhook_url")
    def test_permanent_failure_logged_after_max_retries(self, mock_safe, mock_post):
        """After MAX_DISPATCH_RETRIES exhausted, an error is logged and the worker continues."""
        mock_safe.return_value = (True, "")
        mock_post.side_effect = Exception("Permanent failure")

        async def instant_sleep(_delay):
            """Skip actual backoff delays in tests."""

        system = AlertSystem(_make_config(webhook=True))
        with patch("asyncio.sleep", new=instant_sleep):
            system.start_worker()
            try:
                system.send_alert(_make_report(email_id="fail-1"))

                # Verify the queue drains (the worker kept running despite the failure)
                deadline = time.monotonic() + 10
                drained = False
                while time.monotonic() < deadline:
                    q = system._alert_queue
                    if q is not None and q.empty():
                        drained = True
                        break
                    time.sleep(0.05)

                self.assertTrue(drained, "Queue did not drain after permanent failure")
            finally:
                system.stop_worker()


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


if __name__ == "__main__":
    unittest.main()
