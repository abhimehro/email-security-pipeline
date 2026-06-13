import unittest
from unittest.mock import MagicMock, patch
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import EmailSecurityPipeline


class TestMainErrorHandling(unittest.TestCase):
    def test_analyze_email_error_handling(self):
        """Test that _analyze_email correctly handles exceptions and records them to metrics."""
        with patch("src.main.Config") as mock_config, patch(
            "src.main.EmailIngestionManager"
        ), patch("src.main.SpamAnalyzer"), patch("src.main.NLPThreatAnalyzer"), patch(
            "src.main.MediaAuthenticityAnalyzer"
        ), patch(
            "src.main.AlertSystem"
        ):

            # Setup mock config
            mock_config_instance = mock_config.return_value
            mock_config_instance.system.log_file = "logs/test.log"
            mock_config_instance.system.log_level = "INFO"
            mock_config_instance.system.log_format = "text"
            mock_config_instance.system.log_rotation_size_mb = 10
            mock_config_instance.system.log_rotation_keep_files = 5
            mock_config_instance.system.enable_metrics = True
            mock_config_instance.email_accounts = []
            mock_config_instance.analysis = MagicMock()
            mock_config_instance.alerts = MagicMock()

            # Initialize pipeline
            pipeline = EmailSecurityPipeline(".env")

            # Setup mock email_data
            email_data = MagicMock()
            email_data.subject = "Test Subject"

            # Mock _run_analysis_layers to raise exception
            pipeline._run_analysis_layers = MagicMock(
                side_effect=Exception("Test Exception for Analysis Error Path")
            )

            # Mock logger and metrics
            pipeline.logger = MagicMock()
            pipeline.metrics = MagicMock()

            # Call _analyze_email
            pipeline._analyze_email(email_data)

            # Verify error was logged and metric recorded
            pipeline.logger.error.assert_called_once()
            error_msg = pipeline.logger.error.call_args[0][0]
            self.assertTrue(
                error_msg.startswith(
                    "Error analyzing email: Test Exception for Analysis Error Path"
                )
            )
            self.assertTrue(pipeline.logger.error.call_args[1].get("exc_info"))
            pipeline.metrics.record_error.assert_called_once_with("analysis_error")



    @patch("src.main.sys.exit")
    @patch("builtins.print")
    def test_start_configuration_error(self, mock_print, mock_exit):
        """Test that start() handles ConfigurationError correctly."""
        from src.utils.config import ConfigurationError
        with patch("src.main.Config") as mock_config, patch(
            "src.main.EmailIngestionManager"
        ), patch("src.main.SpamAnalyzer"), patch("src.main.NLPThreatAnalyzer"), patch(
            "src.main.MediaAuthenticityAnalyzer"
        ), patch(
            "src.main.AlertSystem"
        ):
            # Setup mock config to avoid logging init errors
            mock_config_instance = mock_config.return_value
            mock_config_instance.system.log_file = "logs/test.log"
            mock_config_instance.system.log_level = "INFO"
            mock_config_instance.system.log_format = "text"
            mock_config_instance.system.log_rotation_size_mb = 10
            mock_config_instance.system.log_rotation_keep_files = 5

            pipeline = EmailSecurityPipeline(".env")
            pipeline.config.validate.side_effect = ConfigurationError(["Test config error"])
            pipeline.stop = MagicMock()
            mock_exit.side_effect = SystemExit(1)

            with self.assertRaises(SystemExit):
                pipeline.start()

            pipeline.stop.assert_called_once()
            mock_exit.assert_called_once_with(1)

    @patch("src.main.sys.exit")
    def test_start_general_exception(self, mock_exit):
        """Test that start() handles general Exception correctly."""
        with patch("src.main.Config") as mock_config, patch(
            "src.main.EmailIngestionManager"
        ), patch("src.main.SpamAnalyzer"), patch("src.main.NLPThreatAnalyzer"), patch(
            "src.main.MediaAuthenticityAnalyzer"
        ), patch(
            "src.main.AlertSystem"
        ):
            # Setup mock config to avoid logging init errors
            mock_config_instance = mock_config.return_value
            mock_config_instance.system.log_file = "logs/test.log"
            mock_config_instance.system.log_level = "INFO"
            mock_config_instance.system.log_format = "text"
            mock_config_instance.system.log_rotation_size_mb = 10
            mock_config_instance.system.log_rotation_keep_files = 5

            pipeline = EmailSecurityPipeline(".env")
            pipeline.config.validate.side_effect = Exception("General error")
            pipeline.logger = MagicMock()
            pipeline.stop = MagicMock()
            mock_exit.side_effect = SystemExit(1)

            with self.assertRaises(SystemExit):
                pipeline.start()

            pipeline.logger.error.assert_called_once()
            pipeline.stop.assert_called_once()
            mock_exit.assert_called_once_with(1)


if __name__ == "__main__":
    unittest.main()
