import unittest
from unittest.mock import MagicMock, patch
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import EmailSecurityPipeline

class TestMainErrorHandling(unittest.TestCase):
    @patch('src.main.Config')
    @patch('src.main.EmailIngestionManager')
    @patch('src.main.SpamAnalyzer')
    @patch('src.main.NLPThreatAnalyzer')
    @patch('src.main.MediaAuthenticityAnalyzer')
    @patch('src.main.AlertSystem')
    def test_analyze_email_error_handling(
        self,
        mock_alert_system,
        mock_media_analyzer,
        mock_nlp_analyzer,
        mock_spam_analyzer,
        mock_ingestion_manager,
        mock_config
    ):
        """Test that _analyze_email correctly handles exceptions and records them to metrics."""
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
        pipeline._run_analysis_layers = MagicMock(side_effect=Exception("Test Exception for Analysis Error Path"))

        # Mock logger and metrics
        pipeline.logger = MagicMock()
        pipeline.metrics = MagicMock()

        # Call _analyze_email
        pipeline._analyze_email(email_data)

        # Verify error was logged and metric recorded
        pipeline.logger.error.assert_called_once()
        error_msg = pipeline.logger.error.call_args[0][0]
        self.assertTrue(error_msg.startswith("Error analyzing email: Test Exception for Analysis Error Path"))
        self.assertTrue(pipeline.logger.error.call_args[1].get('exc_info'))
        pipeline.metrics.record_error.assert_called_once_with("analysis_error")

if __name__ == '__main__':
    unittest.main()
