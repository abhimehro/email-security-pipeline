"""
Unit tests for src/main.py.

Tests the CLI entry point, EmailSecurityPipeline lifecycle,
monitoring loop, email analysis, logging setup, and summary reporting.
"""

from concurrent.futures import TimeoutError
from unittest.mock import MagicMock, patch

import pytest

from src.main import EmailSecurityPipeline, main
from src.modules.email_ingestion import EmailAccountConfig


def _create_mock_pipeline_config(
    enable_metrics: bool = True,
    log_format: str = "text",
    accounts: list | None = None,
):
    """Helper to build a mock Config instance for EmailSecurityPipeline."""
    mock_config = MagicMock()
    mock_config.system.log_file = "logs/test.log"
    mock_config.system.log_level = "INFO"
    mock_config.system.log_format = log_format
    mock_config.system.log_rotation_size_mb = 10
    mock_config.system.log_rotation_keep_files = 5
    mock_config.system.enable_metrics = enable_metrics
    mock_config.system.rate_limit_delay = 1.0
    mock_config.system.max_attachment_size_mb = 10
    mock_config.system.max_total_attachment_size_mb = 25
    mock_config.system.max_attachment_count = 5
    mock_config.system.max_body_size_kb = 500
    mock_config.system.max_parallel_accounts = 2
    mock_config.system.max_emails_per_batch = 10
    mock_config.system.check_interval = 60

    mock_config.email_accounts = accounts or []
    mock_config.analysis.spam_threshold = 0.7
    mock_config.analysis.nlp_threshold = 0.6
    mock_config.analysis.check_media_attachments = True
    mock_config.analysis.deepfake_detection_enabled = True

    mock_config.alerts.console = True
    mock_config.alerts.webhook_enabled = False
    mock_config.alerts.slack_enabled = False

    return mock_config


class TestMainEntryPoint:
    """Tests for the main() entry point."""

    @patch("src.main.AppRunner")
    def test_main_invokes_app_runner(self, mock_app_runner_cls):
        """Verify main() instantiates AppRunner and executes run()."""
        mock_runner = MagicMock()
        mock_app_runner_cls.return_value = mock_runner

        main()

        mock_app_runner_cls.assert_called_once()
        mock_runner.run.assert_called_once()


class TestPipelineInitialization:
    """Tests for EmailSecurityPipeline initialization and logging setup."""

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_init_with_metrics_enabled(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """Pipeline initializes with metrics when enable_metrics is True."""
        mock_cfg = _create_mock_pipeline_config(enable_metrics=True)
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")

        assert pipeline.metrics is not None
        assert pipeline.running is False
        assert pipeline.executor is not None
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_init_with_metrics_disabled(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """Pipeline initializes with metrics as None when enable_metrics is False."""
        mock_cfg = _create_mock_pipeline_config(enable_metrics=False)
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")

        assert pipeline.metrics is None
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.RotatingFileHandler")
    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_setup_logging_json_format(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        mock_file_handler_cls,
        tmp_path,
    ):
        """When log_format is json, JSONFormatter is attached to the file handler."""
        mock_cfg = _create_mock_pipeline_config(log_format="json")
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg
        mock_handler_instance = MagicMock()
        mock_file_handler_cls.return_value = mock_handler_instance

        with patch("src.main.JSONFormatter") as mock_json_formatter_cls:
            mock_formatter = MagicMock()
            mock_json_formatter_cls.return_value = mock_formatter

            pipeline = EmailSecurityPipeline(".env")
            mock_handler_instance.setFormatter.assert_any_call(mock_formatter)
            pipeline.executor.shutdown(wait=False)


class TestPipelineLifecycle:
    """Tests for start() and stop() methods."""

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_start_success(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """start() validates config, initializes clients, starts alert worker, and begins monitoring."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.ingestion_manager.initialize_clients.return_value = True
        pipeline._print_configuration_summary = MagicMock()
        pipeline._monitoring_loop = MagicMock()

        pipeline.start()

        pipeline.config.validate.assert_called_once()
        pipeline._print_configuration_summary.assert_called_once()
        pipeline.ingestion_manager.initialize_clients.assert_called_once()
        pipeline.alert_system.start_worker.assert_called_once()
        pipeline._monitoring_loop.assert_called_once()
        assert pipeline.running is True
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.sys.exit")
    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_start_client_initialization_failure(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        mock_exit,
        tmp_path,
    ):
        """When client initialization fails, pipeline stops and exits with code 1."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg
        mock_exit.side_effect = SystemExit(1)

        pipeline = EmailSecurityPipeline(".env")
        pipeline.ingestion_manager.initialize_clients.return_value = False
        pipeline._print_configuration_summary = MagicMock()
        pipeline.stop = MagicMock()

        with pytest.raises(SystemExit) as excinfo:
            pipeline.start()

        assert excinfo.value.code == 1
        pipeline.stop.assert_called_once()
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_start_keyboard_interrupt(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """When KeyboardInterrupt occurs during start, pipeline stops cleanly."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.ingestion_manager.initialize_clients.return_value = True
        pipeline._print_configuration_summary = MagicMock()
        pipeline._monitoring_loop = MagicMock(side_effect=KeyboardInterrupt)
        pipeline.stop = MagicMock()

        pipeline.start()

        pipeline.stop.assert_called_once()
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_stop_teardown_flow(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """stop() tears down connections, alert worker, executor, and media analyzer."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.running = True

        pipeline.stop()

        assert pipeline.running is False
        pipeline.ingestion_manager.close_all_connections.assert_called_once()
        pipeline.alert_system.stop_worker.assert_called_once()
        pipeline.media_analyzer.shutdown.assert_called_once()

    @patch("src.main.ThreadPoolExecutor")
    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_stop_media_analyzer_shutdown_timeout(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        mock_thread_pool,
        tmp_path,
    ):
        """stop() catches TimeoutError on media analyzer shutdown without crashing."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        mock_shutdown_executor = MagicMock()
        mock_future = MagicMock()
        mock_future.result.side_effect = TimeoutError("Timed out")
        mock_shutdown_executor.submit.return_value = mock_future
        # First call is pipeline.executor init, subsequent is in stop()
        pipeline_executor = MagicMock()
        mock_thread_pool.side_effect = [pipeline_executor, mock_shutdown_executor]

        pipeline = EmailSecurityPipeline(".env")
        pipeline.logger = MagicMock()

        pipeline.stop()

        pipeline.logger.warning.assert_called_once()
        mock_shutdown_executor.shutdown.assert_called_once_with(wait=False)


class TestMonitoringLoop:
    """Tests for _monitoring_loop()."""

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_monitoring_loop_no_emails(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """When no emails are fetched, the loop logs and continues cleanly."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.running = True
        pipeline.ingestion_manager.fetch_all_emails.return_value = []

        # Stop after one iteration
        def stop_after_fetch(*args, **kwargs):
            pipeline.running = False
            return []

        pipeline.ingestion_manager.fetch_all_emails.side_effect = stop_after_fetch

        pipeline._monitoring_loop()

        pipeline.ingestion_manager.fetch_all_emails.assert_called_once_with(
            pipeline.config.system.max_emails_per_batch
        )
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.CountdownTimer.wait")
    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_monitoring_loop_processes_emails_and_metrics_summary(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        mock_timer_wait,
        tmp_path,
    ):
        """When emails are found, _analyze_email is called and metrics summary logged at iteration 10."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.running = True
        pipeline._analyze_email = MagicMock()
        pipeline._log_metrics_summary = MagicMock()

        iterations = [0]
        email_mock = MagicMock()

        def fetch_side_effect(*args, **kwargs):
            iterations[0] += 1
            if iterations[0] >= 10:
                pipeline.running = False
            return [email_mock]

        pipeline.ingestion_manager.fetch_all_emails.side_effect = fetch_side_effect

        pipeline._monitoring_loop()

        assert pipeline._analyze_email.call_count == 10
        pipeline._log_metrics_summary.assert_called_once()
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.CountdownTimer.wait")
    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_monitoring_loop_handles_exception(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        mock_timer_wait,
        tmp_path,
    ):
        """Exceptions in monitoring loop are logged, recorded in metrics, and pause via CountdownTimer."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.running = True
        pipeline.metrics = MagicMock()

        def fail_then_stop(*args, **kwargs):
            pipeline.running = False
            raise RuntimeError("Transient fetch failure")

        pipeline.ingestion_manager.fetch_all_emails.side_effect = fail_then_stop

        pipeline._monitoring_loop()

        pipeline.metrics.record_error.assert_called_once_with("monitoring_loop_error")
        mock_timer_wait.assert_called_once_with(30, mock_timer_wait.call_args[0][1])
        pipeline.executor.shutdown(wait=False)


class TestEmailAnalysisAndThreatMetrics:
    """Tests for _analyze_email, _run_analysis_layers, and _record_threat_metrics."""

    @patch("src.main.generate_threat_report")
    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_analyze_email_success(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        mock_gen_report,
        tmp_path,
    ):
        """_analyze_email runs analyzers, generates report, sends alert, and records metrics."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.metrics = MagicMock()

        email_data = MagicMock()
        email_data.subject = "Test Phishing Subject"

        spam_result = MagicMock()
        spam_result.score = 0.8
        spam_result.risk_level = "high"

        nlp_result = MagicMock()
        nlp_result.threat_score = 0.9
        nlp_result.risk_level = "high"

        media_result = MagicMock()
        media_result.threat_score = 0.1
        media_result.risk_level = "low"

        pipeline.spam_analyzer.analyze.return_value = spam_result
        pipeline.nlp_analyzer.analyze.return_value = nlp_result
        pipeline.media_analyzer.analyze.return_value = media_result

        threat_report = MagicMock()
        threat_report.overall_threat_score = 0.85
        threat_report.risk_level = "high"
        mock_gen_report.return_value = threat_report

        pipeline._analyze_email(email_data)

        pipeline.alert_system.send_alert.assert_called_once_with(threat_report)
        pipeline.metrics.record_email_processed.assert_called_once()
        pipeline.metrics.record_processing_time.assert_called_once()
        pipeline.metrics.record_threat.assert_called_once_with("phishing", "high")
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_record_threat_metrics_types(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """_record_threat_metrics correctly maps malware, phishing, and spam."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.metrics = MagicMock()

        # Case 1: media analyzer has highest score -> malware
        spam_res = MagicMock(score=0.2)
        nlp_res = MagicMock(threat_score=0.3)
        media_res = MagicMock(threat_score=0.9)
        report = MagicMock(risk_level="HIGH")

        pipeline._record_threat_metrics(report, spam_res, nlp_res, media_res)
        pipeline.metrics.record_threat.assert_called_with("malware", "high")

        # Case 2: spam analyzer has highest score -> spam
        spam_res.score = 0.95
        nlp_res.threat_score = 0.2
        media_res.threat_score = 0.1
        pipeline._record_threat_metrics(report, spam_res, nlp_res, media_res)
        pipeline.metrics.record_threat.assert_called_with("spam", "high")

        # Case 3: low risk level -> does not record threat
        pipeline.metrics.reset_mock()
        report.risk_level = "low"
        pipeline._record_threat_metrics(report, spam_res, nlp_res, media_res)
        pipeline.metrics.record_threat.assert_not_called()

        pipeline.executor.shutdown(wait=False)

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_log_metrics_summary(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        tmp_path,
    ):
        """_log_metrics_summary logs formatted metrics when metrics is enabled."""
        mock_cfg = _create_mock_pipeline_config()
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline.metrics = MagicMock()
        pipeline.metrics.get_summary.return_value = {
            "emails_processed": 5,
            "threats_detected": {"spam": 2},
            "processing_time_stats": {"avg_ms": 120},
        }
        pipeline.logger = MagicMock()

        pipeline._log_metrics_summary()

        pipeline.logger.info.assert_called_once()
        pipeline.logger.debug.assert_called_once()
        pipeline.executor.shutdown(wait=False)


class TestConfigurationSummary:
    """Tests for configuration summary output."""

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_print_configuration_summary_with_accounts_and_alerts(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        capsys,
        tmp_path,
    ):
        """_print_configuration_summary prints account list and enabled alert channels."""
        account_mock = EmailAccountConfig(
            provider="gmail",
            email="user@gmail.com",
            app_password="mock_app_password",
            imap_server="imap.gmail.com",
            imap_port=993,
            folders=["INBOX"],
            use_ssl=True,
            enabled=True,
        )
        mock_cfg = _create_mock_pipeline_config(accounts=[account_mock])
        mock_cfg.alerts.console = True
        mock_cfg.alerts.webhook_enabled = True
        mock_cfg.alerts.slack_enabled = True
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline._print_configuration_summary()

        out = capsys.readouterr().out
        assert "System Configuration:" in out
        assert "Gmail: user@gmail.com" in out
        assert "Console, Webhook, Slack" in out
        assert "README.md" in out
        pipeline.executor.shutdown(wait=False)

    @patch("src.main.AlertSystem")
    @patch("src.main.MediaAuthenticityAnalyzer")
    @patch("src.main.NLPThreatAnalyzer")
    @patch("src.main.SpamAnalyzer")
    @patch("src.main.EmailIngestionManager")
    @patch("src.main.Config")
    def test_print_configuration_summary_empty_state(
        self,
        mock_config_cls,
        mock_ingestion_cls,
        mock_spam_cls,
        mock_nlp_cls,
        mock_media_cls,
        mock_alert_cls,
        capsys,
        tmp_path,
    ):
        """_print_configuration_summary prints guidance when no accounts or alerts configured."""
        mock_cfg = _create_mock_pipeline_config(accounts=[])
        mock_cfg.alerts.console = False
        mock_cfg.alerts.webhook_enabled = False
        mock_cfg.alerts.slack_enabled = False
        mock_cfg.analysis.check_media_attachments = False
        mock_cfg.analysis.deepfake_detection_enabled = False
        mock_cfg.system.log_file = str(tmp_path / "logs" / "test.log")
        mock_config_cls.return_value = mock_cfg

        pipeline = EmailSecurityPipeline(".env")
        pipeline._print_configuration_summary()

        out = capsys.readouterr().out
        assert "No accounts configured" in out
        assert "No alert channels configured" in out
        pipeline.executor.shutdown(wait=False)
