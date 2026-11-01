"""
Unit tests for AlertSystem in src/modules/alert_system.py.

Covers:
- Class constants and initialization
- Worker lifecycle edge cases (timeouts, idempotency, unstarted/closed loops)
- Alert routing and threshold gating in send_alert
- External alert dispatching (_dispatch_alert_async, _dispatch_external_alerts_async, _process_dispatch_results)
- Direct channel alerts (_webhook_alert, _slack_alert) handling SSRF, HTTP status codes, and exceptions
- Delegated console/sanitization/recommendation helper methods
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
    """Build a mock AlertConfig with default test values."""
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


def _create_threat_report(
    email_id="msg-100", score=85.0, risk_level="high", **kwargs
):
    """Build a sample ThreatReport for testing."""
    return ThreatReport(
        email_id=email_id,
        subject=kwargs.get("subject", "Test Threat Subject"),
        sender=kwargs.get("sender", "attacker@evil.com"),
        recipient=kwargs.get("recipient", "victim@example.com"),
        date=kwargs.get("date", "2026-03-30T10:00:00"),
        overall_threat_score=score,
        risk_level=risk_level,
        spam_analysis=kwargs.get("spam_analysis", {}),
        nlp_analysis=kwargs.get("nlp_analysis", {}),
        media_analysis=kwargs.get("media_analysis", {}),
        recommendations=kwargs.get("recommendations", ["Block sender"]),
        timestamp=kwargs.get("timestamp", "2026-03-30T10:00:00"),
    )


class TestAlertSystemInit(unittest.TestCase):
    """Test AlertSystem initialization and class constants."""

    def test_constants_defined(self):
        self.assertEqual(AlertSystem.MAX_SPAM_INDICATORS_DISPLAY, 5)
        self.assertEqual(AlertSystem.MAX_HEADER_ISSUES_DISPLAY, 5)
        self.assertEqual(AlertSystem.MAX_NLP_INDICATORS_DISPLAY, 3)
        self.assertEqual(AlertSystem.MAX_MEDIA_WARNINGS_DISPLAY, 3)
        self.assertEqual(AlertSystem.MAX_URLS_DISPLAY, 3)
        self.assertEqual(AlertSystem.MAX_DISPATCH_RETRIES, 3)
        self.assertEqual(AlertSystem.ALERT_QUEUE_MAX_SIZE, 1000)

    def test_init_state(self):
        config = _create_mock_config()
        system = AlertSystem(config)
        self.assertIs(system.config, config)
        self.assertIsNone(system._loop)
        self.assertIsNone(system._alert_queue)
        self.assertIsNone(system._worker_thread)
        self.assertFalse(system._queue_ready.is_set())


class TestAlertSystemWorkerLifecycle(unittest.TestCase):
    """Test start_worker and stop_worker lifecycle handling."""

    def test_start_worker_readiness_timeout(self):
        config = _create_mock_config()
        system = AlertSystem(config)

        with patch("src.modules.alert_system.threading.Thread") as mock_thread_cls, \
             patch.object(system.logger, "warning") as mock_warning:
            mock_thread = MagicMock()
            mock_thread.is_alive.return_value = True
            mock_thread_cls.return_value = mock_thread

            with patch.object(system._queue_ready, "wait", return_value=False):
                system.start_worker()

            mock_warning.assert_called_once_with(
                "Alert worker did not become ready within 5 s"
            )

    def test_stop_worker_when_unstarted_or_closed(self):
        config = _create_mock_config()
        system = AlertSystem(config)

        # 1. Unstarted loop is None -> returns early
        system.stop_worker()
        self.assertIsNone(system._loop)

        # 2. Loop is closed -> returns early
        loop = asyncio.new_event_loop()
        loop.close()
        system._loop = loop
        system._alert_queue = asyncio.Queue()
        system.stop_worker()

    def test_stop_worker_sentinel_exception_handled(self):
        config = _create_mock_config()
        system = AlertSystem(config)
        mock_loop = MagicMock()
        mock_loop.is_closed.return_value = False
        system._loop = mock_loop
        system._alert_queue = MagicMock()

        with patch("src.modules.alert_system.asyncio.run_coroutine_threadsafe", side_effect=RuntimeError("Loop error")), \
             patch.object(system.logger, "error") as mock_error:
            system.stop_worker()
            mock_error.assert_called_once()
            self.assertIn("Error sending stop sentinel", mock_error.call_args[0][0])

    def test_stop_worker_join_timeout_logs_warning(self):
        config = _create_mock_config()
        system = AlertSystem(config)
        mock_loop = MagicMock()
        mock_loop.is_closed.return_value = False
        system._loop = mock_loop
        system._alert_queue = MagicMock()

        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        system._worker_thread = mock_thread

        mock_fut = MagicMock()
        mock_fut.result.return_value = None

        with patch("src.modules.alert_system.asyncio.run_coroutine_threadsafe", return_value=mock_fut), \
             patch.object(system.logger, "warning") as mock_warning:
            system.stop_worker()
            mock_thread.join.assert_called_once_with(timeout=30)
            mock_warning.assert_called_once_with(
                "Alert worker did not stop within 30 s"
            )


class TestAlertSystemSendAlert(unittest.TestCase):
    """Test send_alert filtering and synchronization logic."""

    def test_send_alert_threat_too_low(self):
        for console_enabled in (False, True):
            with self.subTest(console=console_enabled):
                config = _create_mock_config(console=console_enabled, threat_low=20.0)
                system = AlertSystem(config)
                report = _create_threat_report(score=5.0, risk_level="low")

                with patch.object(system, "_console_clean_report") as mock_clean, \
                     patch.object(system, "_dispatch_alert_sync") as mock_sync:
                    system.send_alert(report)
                    if console_enabled:
                        mock_clean.assert_called_once_with(report)
                    else:
                        mock_clean.assert_not_called()
                    mock_sync.assert_not_called()

    def test_send_alert_dispatches_sync_when_worker_not_running(self):
        config = _create_mock_config(console=True, threat_low=10.0)
        system = AlertSystem(config)
        report = _create_threat_report(score=80.0, risk_level="high")

        with patch.object(system, "_dispatch_alert_sync") as mock_sync:
            system.send_alert(report)
            mock_sync.assert_called_once_with(report)

    def test_dispatch_alert_sync_invokes_all_configured_channels(self):
        config = _create_mock_config(
            console=True,
            webhook_enabled=True,
            webhook_url="https://example.com/webhook",
            slack_enabled=True,
            slack_webhook="https://hooks.slack.com/services/TEST",
        )
        system = AlertSystem(config)
        report = _create_threat_report()

        with patch.object(system, "_console_alert") as mock_console, \
             patch.object(system, "_webhook_alert") as mock_webhook, \
             patch.object(system, "_slack_alert") as mock_slack:
            system._dispatch_alert_sync(report)
            mock_console.assert_called_once_with(report)
            mock_webhook.assert_called_once_with(report)
            mock_slack.assert_called_once_with(report)


class TestAlertSystemAsyncDispatch(unittest.IsolatedAsyncioTestCase):
    """Test asynchronous dispatching methods."""

    async def test_dispatch_external_alerts_async_no_tasks(self):
        config = _create_mock_config(webhook_enabled=False, slack_enabled=False)
        system = AlertSystem(config)
        report = _create_threat_report()

        failed = await system._dispatch_external_alerts_async(report)
        self.assertEqual(failed, [])

    async def test_dispatch_alert_async_raises_on_channel_failure(self):
        config = _create_mock_config(
            console=True,
            webhook_enabled=True,
            webhook_url="https://example.com/webhook",
        )
        system = AlertSystem(config)
        report = _create_threat_report()

        with patch.object(system, "_console_alert") as mock_console, \
             patch.object(system, "_dispatch_external_alerts_async", return_value=["webhook"]):
            with self.assertRaises(RuntimeError) as ctx:
                await system._dispatch_alert_async(report)
            self.assertIn("webhook", str(ctx.exception))
            mock_console.assert_called_once_with(report)

    def test_process_dispatch_results(self):
        config = _create_mock_config()
        system = AlertSystem(config)

        channel_names = ["webhook", "slack", "pager"]
        results = [True, Exception("Network timeout"), False]

        failed = system._process_dispatch_results(channel_names, results)
        self.assertEqual(failed, ["slack", "pager"])


class TestAlertSystemChannelAlerts(unittest.TestCase):
    """Test webhook and Slack alert execution and error handling with unified helpers."""

    def _get_channel_spec(self, channel: str):
        if channel == "webhook":
            return {
                "config_kwargs": {
                    "webhook_enabled": True,
                    "webhook_url": "https://example.com/webhook",
                },
                "method_name": "_webhook_alert",
                "label": "Webhook",
            }
        return {
            "config_kwargs": {
                "slack_enabled": True,
                "slack_webhook": "https://hooks.slack.com/services/TEST",
            },
            "method_name": "_slack_alert",
            "label": "Slack",
        }

    def test_channels_ssrf_blocked(self):
        for channel in ("webhook", "slack"):
            spec = self._get_channel_spec(channel)
            with self.subTest(channel=channel):
                system = AlertSystem(_create_mock_config(**spec["config_kwargs"]))
                report = _create_threat_report()

                with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(False, "SSRF blocked")), \
                     patch.object(system.logger, "error") as mock_error:
                    dispatch_func = getattr(system, spec["method_name"])
                    result = dispatch_func(report)
                    self.assertFalse(result)
                    mock_error.assert_called_once()
                    self.assertIn("SSRF prevention", mock_error.call_args[0][0])

    def test_channels_success(self):
        for channel in ("webhook", "slack"):
            spec = self._get_channel_spec(channel)
            with self.subTest(channel=channel):
                system = AlertSystem(_create_mock_config(**spec["config_kwargs"]))
                report = _create_threat_report()

                mock_resp = MagicMock(status_code=200)
                with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(True, "")), \
                     patch("src.modules.alert_system.requests.post", return_value=mock_resp), \
                     patch.object(system.logger, "info") as mock_info:
                    dispatch_func = getattr(system, spec["method_name"])
                    result = dispatch_func(report)
                    self.assertTrue(result)
                    mock_info.assert_called_once_with(f"{spec['label']} alert sent successfully")

    def test_channels_non_200_failure(self):
        for channel, code in (("webhook", 500), ("slack", 400)):
            spec = self._get_channel_spec(channel)
            with self.subTest(channel=channel, code=code):
                system = AlertSystem(_create_mock_config(**spec["config_kwargs"]))
                report = _create_threat_report()

                mock_resp = MagicMock(status_code=code)
                with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(True, "")), \
                     patch("src.modules.alert_system.requests.post", return_value=mock_resp), \
                     patch.object(system.logger, "warning") as mock_warn:
                    dispatch_func = getattr(system, spec["method_name"])
                    result = dispatch_func(report)
                    self.assertFalse(result)
                    mock_warn.assert_called_once_with(f"{spec['label']} alert failed: {code}")

    def test_channels_exception_handling(self):
        for channel in ("webhook", "slack"):
            spec = self._get_channel_spec(channel)
            with self.subTest(channel=channel):
                system = AlertSystem(_create_mock_config(**spec["config_kwargs"]))
                report = _create_threat_report()

                with patch("src.modules.alert_system.is_safe_webhook_url", return_value=(True, "")), \
                     patch("src.modules.alert_system.requests.post", side_effect=Exception("Network error")), \
                     patch.object(system.logger, "error") as mock_error:
                    dispatch_func = getattr(system, spec["method_name"])
                    result = dispatch_func(report)
                    self.assertFalse(result)
                    mock_error.assert_called_once()
                    self.assertIn(f"Failed to send {channel} alert".lower(), mock_error.call_args[0][0].lower())


class TestAlertSystemDelegatedHelpers(unittest.TestCase):
    """Test delegated helper methods for console formatting, sanitization, and recommendations."""

    def setUp(self):
        self.config = _create_mock_config()
        self.system = AlertSystem(self.config)

    def test_safe_console_url(self):
        url = "https://example.com/api?token=secret123"
        safe = self.system._safe_console_url(url)
        self.assertNotIn("secret123", safe)

    def test_get_terminal_width(self):
        width = self.system._get_terminal_width()
        self.assertIsInstance(width, int)
        self.assertGreater(width, 0)

    def test_get_visual_length(self):
        text_with_ansi = "\x1b[31mRed text\x1b[0m"
        length = self.system._get_visual_length(text_with_ansi)
        self.assertEqual(length, 8)

    def test_truncate_text(self):
        text = "Hello world from test"
        truncated = self.system._truncate_text(text, 10)
        self.assertEqual(truncated, "Hello w...")

    def test_sanitize_text(self):
        text = "=1+2"
        sanitized = self.system._sanitize_text(text, csv_safe=True)
        self.assertTrue(sanitized.startswith("'"))

    def test_sanitize_for_slack(self):
        raw = "User <malicious> & text"
        sanitized = self.system._sanitize_for_slack(raw)
        self.assertNotIn("<malicious>", sanitized)

    def test_sanitize_error_message(self):
        err = Exception("Failed at https://api.com?secret=abc")
        sanitized = self.system._sanitize_error_message(err)
        self.assertNotIn("secret=abc", sanitized)

    def test_redact_url_secrets(self):
        url = "https://example.com/webhook?token=mysecrettoken"
        redacted = self.system._redact_url_secrets(url)
        self.assertNotIn("mysecrettoken", redacted)

    def test_redact_sensitive_url_params(self):
        url = "https://example.com/webhook?token=mysecrettoken"
        redacted = self.system._redact_sensitive_url_params(url)
        self.assertNotIn("mysecrettoken", redacted)

    def test_generate_recommendations(self):
        spam = SpamAnalysisResult(
            score=0.0,
            indicators=[],
            suspicious_urls=[],
            header_issues=[],
            risk_level="low",
        )
        nlp = NLPAnalysisResult(
            threat_score=0.0,
            social_engineering_indicators=[],
            urgency_markers=[],
            authority_impersonation=[],
            psychological_triggers=[],
            risk_level="low",
        )
        media = MediaAnalysisResult(
            threat_score=0.0,
            suspicious_attachments=[],
            file_type_warnings=[],
            size_anomalies=[],
            potential_deepfakes=[],
            risk_level="low",
        )
        recs = AlertSystem._generate_recommendations(spam, nlp, media)
        self.assertEqual(recs, [AlertSystem.DEFAULT_CLEAN_RECOMMENDATION])
