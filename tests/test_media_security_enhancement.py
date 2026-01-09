
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime
from src.modules.media_analyzer import MediaAuthenticityAnalyzer, MediaAnalysisResult
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaAnalyzerSecurityEnhancement(unittest.TestCase):
    def setUp(self):
        self.config = AnalysisConfig(
            spam_threshold=5.0,
            spam_check_headers=True,
            spam_check_urls=True,
            nlp_model="test",
            nlp_threshold=0.7,
            nlp_batch_size=8,
            check_social_engineering=True,
            check_urgency_markers=True,
            check_authority_impersonation=True,
            check_media_attachments=True,
            deepfake_detection_enabled=True,
            media_analysis_timeout=60,
            deepfake_provider="simulator",
            deepfake_api_key=None,
            deepfake_api_url=None,
            deepfake_model_path=None
        )
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    @patch.object(MediaAuthenticityAnalyzer, '_check_deepfake_indicators')
    def test_skip_deepfake_on_dangerous_mismatch(self, mock_deepfake_check):
        """
        Test that deepfake analysis is skipped when the file content type matches a dangerous executable,
        even if the extension is safe (.mp4).
        """
        # Mock return value for deepfake check
        mock_deepfake_check.return_value = (0.0, [])

        email_data = EmailData(
            message_id="test",
            subject="Test",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="",
            body_html="",
            headers={},
            attachments=[{
                "filename": "innocent_video.mp4",
                "content_type": "video/mp4",
                "size": 1000,
                # 'MZ' indicates an executable (e.g. .exe, .dll)
                "data": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        result = self.analyzer.analyze(email_data)

        # Check if threat score reflects the mismatch (5.0 points)
        # 5.0 for "Executable disguised as another file type"
        self.assertGreaterEqual(result.threat_score, 5.0)

        # CRITICAL CHECK: deepfake detection should NOT be called because the file content indicates
        # it is an executable (MZ header), leading to a high mismatch score.
        if mock_deepfake_check.called:
             print("Deepfake check WAS called (Unexpected)")
        else:
             print("Deepfake check was NOT called (Success)")

        self.assertFalse(mock_deepfake_check.called, "Deepfake check should be skipped for disguised executables")

if __name__ == '__main__':
    unittest.main()
