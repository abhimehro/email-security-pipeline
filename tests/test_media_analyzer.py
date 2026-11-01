import concurrent.futures
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.modules.email_ingestion import EmailData
from src.modules.media_analyzer import MediaAnalysisResult, MediaAuthenticityAnalyzer
from src.utils.config import AnalysisConfig


class TestMediaAnalyzer(unittest.TestCase):
    """Unit tests for MediaAuthenticityAnalyzer and MediaAnalysisResult."""

    def setUp(self):
        self.config = AnalysisConfig(
            spam_threshold=5.0,
            spam_check_headers=True,
            spam_check_urls=True,
            nlp_model="test",
            nlp_model_revision="main",
            nlp_threshold=0.7,
            nlp_batch_size=8,
            check_social_engineering=True,
            check_urgency_markers=True,
            check_authority_impersonation=True,
            check_media_attachments=True,
            deepfake_detection_enabled=True,
            media_analysis_timeout=5,
            deepfake_provider="simulator",
            deepfake_api_key=None,
            deepfake_api_url=None,
            deepfake_model_path=None,
        )
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def tearDown(self):
        self.analyzer.shutdown()

    def _create_email(self, attachments=None):
        return EmailData(
            message_id="test-msg-1",
            subject="Test Subject",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="Test email body",
            body_html="<p>Test email body</p>",
            headers={},
            attachments=attachments or [],
            raw_email=None,
            account_email="recipient@example.com",
            folder="INBOX",
        )

    def test_media_analysis_result_dataclass(self):
        """Test MediaAnalysisResult dataclass initialization and attributes."""
        res = MediaAnalysisResult(
            threat_score=1.5,
            suspicious_attachments=["bad.zip"],
            file_type_warnings=["Dangerous file type"],
            size_anomalies=["File too large"],
            potential_deepfakes=["Face artifact"],
            risk_level="medium",
        )
        self.assertEqual(res.threat_score, 1.5)
        self.assertEqual(res.suspicious_attachments, ["bad.zip"])
        self.assertEqual(res.file_type_warnings, ["Dangerous file type"])
        self.assertEqual(res.size_anomalies, ["File too large"])
        self.assertEqual(res.potential_deepfakes, ["Face artifact"])
        self.assertEqual(res.risk_level, "medium")

    def test_analyze_when_media_check_disabled(self):
        """Test that analyze returns zero scores when check_media_attachments is False."""
        self.config.check_media_attachments = False
        email = self._create_email(
            attachments=[
                {
                    "filename": "danger.exe",
                    "content_type": "application/octet-stream",
                    "size": 1024,
                    "data": b"MZ\x90\x00",
                    "truncated": False,
                }
            ]
        )
        res = self.analyzer.analyze(email)
        self.assertEqual(res.threat_score, 0.0)
        self.assertEqual(res.risk_level, "low")
        self.assertEqual(len(res.suspicious_attachments), 0)
        self.assertEqual(len(res.file_type_warnings), 0)

    def test_analyze_empty_attachments(self):
        """Test that an email without attachments returns empty/low risk results."""
        email = self._create_email(attachments=[])
        res = self.analyzer.analyze(email)
        self.assertEqual(res.threat_score, 0.0)
        self.assertEqual(res.risk_level, "low")
        self.assertEqual(res.suspicious_attachments, [])
        self.assertEqual(res.file_type_warnings, [])
        self.assertEqual(res.size_anomalies, [])
        self.assertEqual(res.potential_deepfakes, [])

    def test_clean_pdf_attachment(self):
        """Test analyzing a clean, valid PDF attachment."""
        pdf_data = b"%PDF-1.4 valid content here"
        email = self._create_email(
            attachments=[
                {
                    "filename": "report.pdf",
                    "content_type": "application/pdf",
                    "size": len(pdf_data),
                    "data": pdf_data,
                    "truncated": False,
                }
            ]
        )
        res = self.analyzer.analyze(email)
        self.assertEqual(res.threat_score, 0.0)
        self.assertEqual(res.risk_level, "low")
        self.assertEqual(res.file_type_warnings, [])
        self.assertEqual(res.suspicious_attachments, [])

    def test_dangerous_file_type_detection(self):
        """Test detection of dangerous executable attachments."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "malware.exe",
                    "content_type": "application/x-msdownload",
                    "size": 1024,
                    "data": b"MZ\x90\x00dummy",
                    "truncated": False,
                }
            ]
        )
        res = self.analyzer.analyze(email)
        self.assertGreaterEqual(res.threat_score, 5.0)
        self.assertEqual(res.risk_level, "high")
        self.assertTrue(any("Dangerous file type" in w for w in res.file_type_warnings))

    def test_suspicious_double_extension_attachment(self):
        """Test detection of suspicious file extensions and double extensions."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "invoice.pdf.exe",
                    "content_type": "application/x-msdownload",
                    "size": 500,
                    "data": b"MZ",
                    "truncated": False,
                }
            ]
        )
        res = self.analyzer.analyze(email)
        self.assertGreaterEqual(res.threat_score, 5.0)
        self.assertTrue(
            any("Multiple extensions detected" in w for w in res.file_type_warnings)
        )

    def test_content_type_mismatch_executable_disguised(self):
        """Test executable disguised with a non-executable extension."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "image.png",
                    "content_type": "image/png",
                    "size": 100,
                    "data": b"MZ\x90\x00fake_image",
                    "truncated": False,
                }
            ]
        )
        res = self.analyzer.analyze(email)
        self.assertGreaterEqual(res.threat_score, 5.0)
        self.assertTrue(
            any(
                "Executable disguised as another file type" in w
                for w in res.suspicious_attachments
            )
        )

    def test_large_size_and_truncated_anomalies(self):
        """Test flagging of oversized and truncated attachments."""
        large_size = (self.analyzer.MAX_ATTACHMENT_SIZE_MB + 1) * 1024 * 1024
        email = self._create_email(
            attachments=[
                {
                    "filename": "huge_file.dat",
                    "content_type": "application/octet-stream",
                    "size": large_size,
                    "data": b"random_bytes",
                    "truncated": True,
                }
            ]
        )
        res = self.analyzer.analyze(email)
        self.assertTrue(
            any("Attachment truncated for scanning" in a for a in res.size_anomalies)
        )
        self.assertTrue(
            any("Unusually large attachment" in a for a in res.size_anomalies)
        )

    def test_deepfake_analysis_flow(self):
        """Test deepfake analysis flow when analyzing a media attachment."""
        with patch.object(
            self.analyzer,
            "_check_deepfake_indicators",
            return_value=(2.5, ["Potential temporal inconsistency"]),
        ) as mock_check:
            email = self._create_email(
                attachments=[
                    {
                        "filename": "presentation.mp4",
                        "content_type": "video/mp4",
                        "size": 2048,
                        "data": b"\x00\x00\x00\x18ftypmp42",
                        "truncated": False,
                    }
                ]
            )
            res = self.analyzer.analyze(email)
            mock_check.assert_called_once()
            self.assertIn("Potential temporal inconsistency", res.potential_deepfakes)
            self.assertGreaterEqual(res.threat_score, 2.5)

    def test_deepfake_stop_threshold_gating(self):
        """Test that once threat_score >= 5.0, subsequent deepfake checks are stopped."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "bad.exe",
                    "content_type": "application/x-msdownload",
                    "size": 1024,
                    "data": b"MZ\x00",
                    "truncated": False,
                },
                {
                    "filename": "sample.mp4",
                    "content_type": "video/mp4",
                    "size": 2048,
                    "data": b"\x00\x00\x00\x18ftypmp42",
                    "truncated": False,
                },
            ]
        )
        with patch.object(
            self.analyzer, "_check_deepfake_indicators"
        ) as mock_deepfake:
            res = self.analyzer.analyze(email)
            self.assertGreaterEqual(res.threat_score, 5.0)
            mock_deepfake.assert_not_called()

    def test_deepfake_analysis_timeout_handling(self):
        """Test handling of TimeoutError during deepfake analysis."""
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError("Timeout")

        with patch.object(
            self.analyzer._deepfake_executor, "submit", return_value=mock_future
        ):
            res = self.analyzer._analyze_deepfake_threat(
                "video.mp4", b"data", "video/mp4"
            )
            self.assertEqual(res["score"], 0.0)
            self.assertTrue(
                any("Deepfake analysis timed out" in err for err in res["errors"])
            )

    def test_deepfake_analysis_generic_exception_handling(self):
        """Test handling of unexpected exceptions during deepfake analysis."""
        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("OpenCV unexpected error")

        with patch.object(
            self.analyzer._deepfake_executor, "submit", return_value=mock_future
        ):
            res = self.analyzer._analyze_deepfake_threat(
                "video.mp4", b"data", "video/mp4"
            )
            self.assertEqual(res["score"], 0.0)
            self.assertEqual(res["indicators"], [])

    def test_shutdown_executors(self):
        """Test that shutdown calls shutdown on both thread pool executors."""
        analyzer = MediaAuthenticityAnalyzer(self.config)
        self.assertFalse(analyzer._deepfake_executor._shutdown)
        self.assertFalse(analyzer._attachment_executor._shutdown)
        analyzer.shutdown()
        self.assertTrue(analyzer._deepfake_executor._shutdown)
        self.assertTrue(analyzer._attachment_executor._shutdown)


if __name__ == "__main__":
    unittest.main()
