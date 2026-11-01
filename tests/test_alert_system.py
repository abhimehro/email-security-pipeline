"""
Unit tests for AlertSystem in src/modules/alert_system.py.
"""

import asyncio
import unittest
from unittest.mock import MagicMock, patch

from src.modules.alert_report import ThreatReport
from src.modules.alert_system import AlertSystem
from src.modules.media_analyzer import MediaAnalysisResult
from src.modules.nlp_analyzer import NLPAnalysisResult
from src.modules.spam_analyzer import SpamAnalysisResult
from src.utils.config import AlertConfig


def _create_mock_config(**kwargs):
    config = MagicMock(spec=AlertConfig)
    config.console = kwargs.get("console", False)
    config.webhook_enabled = kwargs.get("webhook_enabled", False)
    config.webhook_url = kwargs.get("webhook_url", "")
    config.slack_enabled = kwargs.get("slack_enabled", False)
    config.slack_webhook = kwargs.get("slack_webhook", "")
    config.threat_low = kwargs.get("threat_low", 10.0)
    config.threat_medium = kwargs.get("threat_medium", 50.0)
    config.threat_high = kwargs.get("threat_high", 80.0)
    return config


def _create_threat_report(email_id="msg-100", score=85.0, risk_level="high"):
    return ThreatReport(
        email_id=email_id,
        subject="Test Threat Subject",
        sender="attacker@evil.com",
        recipient="victim@example.com",
        date="2026-03-30T10:00:00",
        overall_threat_score=score,
        risk_level=risk_level,
        spam_analysis={},
        nlp_analysis={},
        media_analysis={},
        recommendations=["Block sender"],
        timestamp="2026-03-30T10:00:00",
    )


class TestAlertSystemInit(unittest.TestCase):
    """Test AlertSystem initialization and class constants."""

    def test_constants_and_init(self):
        for attr, val in (
            ("MAX_SPAM_INDICATORS_DISPLAY", 5),
            ("MAX_HEADER_ISSUES_DISPLAY", 5),
            ("MAX_NLP_INDICATORS_DISPLAY", 3),
            ("MAX_MEDIA_WARNINGS_DISPLAY", 3),
            ("MAX_URLS_DISPLAY", 3),
            ("MAX_DISPATCH_RETRIES", 3),
            ("ALERT_QUEUE_MAX_SIZE", 1000),
        ):
            self.assertEqual(getattr(AlertSystem, attr), val)

        cfg = _create_mock_config()
        sys = AlertSystem(cfg)
        self.assertIs(sys.config, cfg)
        self.assertIsNone(sys._loop)
        self.assertIsNone(sys._alert_queue)
        self.assertIsNone(sys._worker_thread)
        self.assertFalse(sys._queue_ready.is_set())


class TestAlertSystemWorkerLifecycle(unittest.TestCase):
    """Test worker lifecycle methods and failure handling."""

    def test_start_worker_readiness_timeout(self):
        system = AlertSystem(_create_mock_config())
        with patch("src.modules.alert_system.threading.Thread") as mock_cls, \
             patch.object(system.logger, "warning") as mock_warn:
            mock_cls.return_value = MagicMock(is_alive=lambda: True)
            with patch.object(system._queue_ready, "wait", return_value=False):
                system.start_worker()
            mock_warn.assert_called_once_with(
                "Alert worker did not become ready within 5 s"
            )

    def test_stop_worker_conditions(self):
        system = AlertSystem(_create_mock_config())

        # Unstarted loop returns early
        system.stop_worker()
        self.assertIsNone(system._loop)

        # Closed loop returns early
        closed_loop = asyncio.new_event_loop()
        closed_loop.close()
        system._loop = closed_loop
        system._alert_queue = asyncio.Queue()
        system.stop_worker()

        # Enqueue exception handled
        mock_loop = MagicMock(is_closed=lambda: False)
        mock_queue = MagicMock()
        mock_queue.put = MagicMock(return_value=None)
        system._loop = mock_loop
        system._alert_queue = mock_queue
        with patch("src.modules.alert_system.asyncio.run_coroutine_threadsafe", side_effect=RuntimeError("Loop err")), \
             patch.object(system.logger, "error") as mock_err:
            system.stop_worker()
            mock_err.assert_called_once()
            self.assertIn("Error sending stop sentinel", mock_err.call_args[0][0])

        # Thread join timeout logs warning
        fut = MagicMock(result=lambda timeout=None: None)
        mock_thread = MagicMock(is_alive=lambda: True)
        system._worker_thread = mock_thread
        with patch("src.modules.alert_system.asyncio.run_coroutine_threadsafe", return_value=fut), \
             patch.object(system.logger, "warning") as mock_warn:
            system.stop_worker()
            mock_warn.assert_called_once_with("Alert worker did not stop within 30 s")


class TestAlertSystemDispatching(unittest.IsolatedAsyncioTestCase):
    """Test alert dispatching logic and gating."""

    def test_send_alert_filtering_and_sync(self):
        rep_low = _create_threat_report(score=5.0, risk_level="low")
        rep_high = _create_threat_report(score=80.0, risk_level="high")

        # Below floor, no console
        s1 = AlertSystem(_create_mock_config(console=False, threat_low=20.0))
        with patch.object(s1, "_console_clean_report") as mc, patch.object(s1, "_dispatch_alert_sync") as ms:
            s1.send_alert(rep_low)
            mc.assert_not_called()
            ms.assert_not_called()

        # Below floor, console enabled
        s2 = AlertSystem(_create_mock_config(console=True, threat_low=20.0))
        with patch.object(s2, "_console_clean_report") as mc, patch.object(s2, "_dispatch_alert_sync") as ms:
            s2.send_alert(rep_low)
            mc.assert_called_once_with(rep_low)
            ms.assert_not_called()

        # Worker unstarted -> synchronous fallback
        s3 = AlertSystem(_create_mock_config(console=True, threat_low=10.0))
        with patch.object(s3, "_dispatch_alert_sync") as ms:
            s3.send_alert(rep_high)
            ms.assert_called_once_with(rep_high)

    def test_dispatch_alert_sync(self):
        sys = AlertSystem(_create_mock_config(
            console=True,
            webhook_enabled=True, webhook_url="https://example.com/webhook",
            slack_enabled=True, slack_webhook="https://hooks.slack.com/services/TEST",
        ))
        rep = _create_threat_report()
        with patch.object(sys, "_console_alert") as c, \
             patch.object(sys, "_webhook_alert") as w, \
             patch.object(sys, "_slack_alert") as s:
            sys._dispatch_alert_sync(rep)
            c.assert_called_once_with(rep)
            w.assert_called_once_with(rep)
            s.assert_called_once_with(rep)

    async def test_async_dispatch_and_results(self):
        sys = AlertSystem(_create_mock_config())
        rep = _create_threat_report()

        # Empty tasks
        res = await sys._dispatch_external_alerts_async(rep)
        self.assertEqual(res, [])

        # Failed channel raises RuntimeError
        sys.config.console = True
        with patch.object(sys, "_console_alert") as c, \
             patch.object(sys, "_dispatch_external_alerts_async", return_value=["webhook"]):
            with self.assertRaises(RuntimeError) as ctx:
                await sys._dispatch_alert_async(rep)
            self.assertIn("webhook", str(ctx.exception))
            c.assert_called_once_with(rep)

        # Process results
        failed = sys._process_dispatch_results(["a", "b", "c"], [True, Exception("fail"), False])
        self.assertEqual(failed, ["b", "c"])


class TestAlertSystemChannels(unittest.TestCase):
    """Test channel delivery handlers."""

    def test_channel_matrix(self):
        cases = [
            ("webhook", "_webhook_alert", {"webhook_enabled": True, "webhook_url": "https://a.com/w"}),
            ("slack", "_slack_alert", {"slack_enabled": True, "slack_webhook": "https://hooks.slack.com/s"}),
        ]
        rep = _create_threat_report()

        for name, method, cfg_kw in cases:
            sys = AlertSystem(_create_mock_config(**cfg_kw))
            fn = getattr(sys, method)

            # SSRF blocked
            with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(False, "blocked")):
                self.assertFalse(fn(rep))

            # 200 Success
            with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(True, "")), \
                 patch("src.modules.alert_system.requests.post", return_value=MagicMock(status_code=200)):
                self.assertTrue(fn(rep))

            # Non-200 Failure
            with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(True, "")), \
                 patch("src.modules.alert_system.requests.post", return_value=MagicMock(status_code=500)):
                self.assertFalse(fn(rep))

            # Exception
            with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(True, "")), \
                 patch("src.modules.alert_system.requests.post", side_effect=Exception("timeout")):
                self.assertFalse(fn(rep))


class TestAlertSystemHelpers(unittest.TestCase):
    """Test helper functions and delegations."""

    def test_helpers(self):
        sys = AlertSystem(_create_mock_config())

        self.assertNotIn("sec_val", sys._safe_console_url("https://ex.com?token=sec_val"))
        self.assertGreater(sys._get_terminal_width(), 0)
        self.assertEqual(sys._get_visual_length("\x1b[31mRed\x1b[0m"), 3)
        self.assertEqual(sys._truncate_text("Hello World", 8), "Hello...")
        self.assertTrue(sys._sanitize_text("=cmd", csv_safe=True).startswith("'"))
        self.assertNotIn("<bad>", sys._sanitize_for_slack("Hello <bad> world"))
        self.assertNotIn("s3cr3t", sys._sanitize_error_message(Exception("err https://e.com?token=s3cr3t")))
        self.assertNotIn("s3cr3t", sys._redact_url_secrets("https://e.com?token=s3cr3t"))
        self.assertNotIn("s3cr3t", sys._redact_sensitive_url_params("https://e.com?token=s3cr3t"))

        spam = SpamAnalysisResult(score=0.0, indicators=[], suspicious_urls=[], header_issues=[], risk_level="low")
        nlp = NLPAnalysisResult(threat_score=0.0, social_engineering_indicators=[], urgency_markers=[], authority_impersonation=[], psychological_triggers=[], risk_level="low")
        media = MediaAnalysisResult(threat_score=0.0, suspicious_attachments=[], file_type_warnings=[], size_anomalies=[], potential_deepfakes=[], risk_level="low")
        self.assertEqual(AlertSystem._generate_recommendations(spam, nlp, media), [AlertSystem.DEFAULT_CLEAN_RECOMMENDATION])
