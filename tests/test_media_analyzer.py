"""Unit tests for MediaAuthenticityAnalyzer."""

import unittest
from concurrent.futures import Future
from datetime import datetime
from typing import NamedTuple
from unittest.mock import patch

from src.modules.email_data import EmailData
from src.modules.media_analyzer import (
    MediaAnalysisResult,
    MediaAuthenticityAnalyzer,
)
from src.utils.config import AnalysisConfig


class RiskTestCase(NamedTuple):
    score: float
    expected_risk: str


class TestMediaAnalyzer(unittest.TestCase):
    """Test suite for MediaAuthenticityAnalyzer."""

    def setUp(self):
        """Set up test fixtures."""
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
        """Clean up analyzer executors."""
        self.analyzer.shutdown()

    def _create_email(self, attachments=None):
        """Create sample EmailData fixture."""
        return EmailData(
            message_id="msg-101",
            subject="Test Media",
            sender="alice@example.com",
            recipient="bob@example.com",
            date=datetime.now(),
            body_text="Test email body",
            body_html="<p>Test email body</p>",
            headers={},
            attachments=attachments or [],
            raw_email=None,
            account_email="bob@example.com",
            folder="INBOX",
        )

    def test_analyze_no_attachments_returns_zero_score(self):
        """Test analyze with empty attachment list returns low risk."""
        email = self._create_email(attachments=[])
        result = self.analyzer.analyze(email)

        self.assertIsInstance(result, MediaAnalysisResult)
        self.assertEqual(result.threat_score, 0.0)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.suspicious_attachments, [])

    def test_analyze_check_disabled_returns_early(self):
        """Test analyze early exit when check_media_attachments is disabled."""
        self.config.check_media_attachments = False
        email = self._create_email(
            attachments=[{"filename": "danger.exe", "data": b"bad"}]
        )
        result = self.analyzer.analyze(email)

        self.assertEqual(result.threat_score, 0.0)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.suspicious_attachments, [])

    def test_analyze_safe_attachment(self):
        """Test analyze on benign attachment returns safe result."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "document.pdf",
                    "data": b"%PDF-1.4 benign pdf content",
                    "content_type": "application/pdf",
                }
            ]
        )
        result = self.analyzer.analyze(email)

        self.assertEqual(result.threat_score, 0.0)
        self.assertEqual(result.risk_level, "low")
        self.assertEqual(result.suspicious_attachments, [])

    def test_analyze_dangerous_attachment_high_risk(self):
        """Test analyze on dangerous extension flags warnings and high risk."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "invoice.pdf.exe",
                    "data": b"MZ executable payload",
                    "content_type": "application/octet-stream",
                }
            ]
        )
        result = self.analyzer.analyze(email)

        self.assertGreaterEqual(result.threat_score, 5.0)
        self.assertEqual(result.risk_level, "high")
        self.assertTrue(len(result.file_type_warnings) > 0)
        self.assertIn("Dangerous file type: invoice.pdf.exe", result.file_type_warnings)

    def test_analyze_content_mismatch_flags_suspicious_attachment(self):
        """Test analyze flags suspicious_attachments on content type mismatch."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "report.pdf",
                    "data": b"MZ executable pretending to be PDF",
                    "content_type": "application/pdf",
                }
            ]
        )
        result = self.analyzer.analyze(email)

        self.assertGreaterEqual(result.threat_score, 3.0)
        self.assertTrue(len(result.suspicious_attachments) > 0)

    def test_analyze_stops_deepfake_when_threshold_exceeded(self):
        """Test stop_deepfake flag activates when metadata score >= 5.0."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "payload.exe",
                    "data": b"MZ malware",
                    "content_type": "application/x-msdownload",
                },
                {
                    "filename": "video.mp4",
                    "data": b"video content",
                    "content_type": "video/mp4",
                },
            ]
        )

        with patch.object(
            self.analyzer, "_analyze_deepfake_threat"
        ) as mock_deepfake:
            result = self.analyzer.analyze(email)
            mock_deepfake.assert_not_called()
            self.assertGreaterEqual(result.threat_score, 5.0)

    def test_analyze_deepfake_accumulation_and_threshold_cutoff(self):
        """Test deepfake results accumulation and threshold cutoff."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "clip1.mp4",
                    "data": b"fake1",
                    "content_type": "video/mp4",
                },
                {
                    "filename": "clip2.mp4",
                    "data": b"fake2",
                    "content_type": "video/mp4",
                },
            ]
        )

        mock_meta = {
            "score": 1.0,
            "size_anomalies": [],
            "file_type_warnings": [],
            "suspicious_attachments": [],
        }
        mock_df1 = {
            "score": 5.0,
            "indicators": ["deepfake detected"],
            "errors": ["minor warning"],
        }
        mock_df2 = {
            "score": 3.0,
            "indicators": ["another deepfake"],
            "errors": [],
        }

        with (
            patch.object(
                self.analyzer,
                "_analyze_attachment_metadata",
                return_value=mock_meta,
            ),
            patch.object(
                self.analyzer,
                "_analyze_deepfake_threat",
                side_effect=[mock_df1, mock_df2],
            ),
        ):
            result = self.analyzer.analyze(email)
            self.assertIn("deepfake detected", result.potential_deepfakes)
            self.assertIn("minor warning", result.size_anomalies)
            self.assertGreaterEqual(result.threat_score, 6.0)
            self.assertEqual(result.risk_level, "high")

    def test_analyze_empty_deepfake_results_skipped(self):
        """Test analyze continues when deepfake_results is None."""
        email = self._create_email(
            attachments=[
                {
                    "filename": "clip.mp4",
                    "data": b"data",
                    "content_type": "video/mp4",
                }
            ]
        )
        mock_meta = {
            "score": 1.0,
            "size_anomalies": [],
            "file_type_warnings": [],
            "suspicious_attachments": [],
        }

        with (
            patch.object(
                self.analyzer,
                "_analyze_attachment_metadata",
                return_value=mock_meta,
            ),
            patch.object(
                self.analyzer,
                "_analyze_deepfake_threat",
                return_value=None,
            ),
        ):
            result = self.analyzer.analyze(email)
            self.assertEqual(result.threat_score, 1.0)
            self.assertEqual(result.potential_deepfakes, [])

    def test_process_attachment_parallel_disabled_deepfake(self):
        """Test parallel attachment processing when deepfake is disabled."""
        self.config.deepfake_detection_enabled = False
        attachment = {"filename": "video.mp4", "data": b"data"}
        shared_state = {"stop_deepfake": False}

        meta_res, df_res = self.analyzer._process_attachment_parallel(
            attachment, shared_state
        )
        self.assertIsNotNone(meta_res)
        self.assertIsNone(df_res)

    def test_process_attachment_parallel_stopped_deepfake(self):
        """Test parallel attachment processing when stop_deepfake is True."""
        attachment = {"filename": "video.mp4", "data": b"data"}
        shared_state = {"stop_deepfake": True}

        meta_res, df_res = self.analyzer._process_attachment_parallel(
            attachment, shared_state
        )
        self.assertIsNotNone(meta_res)
        self.assertIsNone(df_res)

    def test_process_attachment_parallel_high_meta_score(self):
        """Test parallel attachment skips deepfake when meta score >= 5.0."""
        attachment = {"filename": "trojan.exe", "data": b"MZ"}
        shared_state = {"stop_deepfake": False}

        with patch.object(
            self.analyzer,
            "_analyze_attachment_metadata",
            return_value={"score": 5.0},
        ):
            meta_res, df_res = self.analyzer._process_attachment_parallel(
                attachment, shared_state
            )
            self.assertEqual(meta_res["score"], 5.0)
            self.assertIsNone(df_res)

    def test_analyze_deepfake_threat_success(self):
        """Test _analyze_deepfake_threat on normal execution."""
        mock_future = Future()
        mock_future.set_result((2.5, ["facial artifact"]))

        with patch.object(
            self.analyzer._deepfake_executor, "submit", return_value=mock_future
        ):
            res = self.analyzer._analyze_deepfake_threat(
                "video.mp4", b"bytes", "video/mp4"
            )
            self.assertEqual(res["score"], 2.5)
            self.assertEqual(res["indicators"], ["facial artifact"])
            self.assertEqual(res["errors"], [])

    def test_analyze_deepfake_threat_timeout(self):
        """Test _analyze_deepfake_threat handles TimeoutError gracefully."""
        mock_future = Future()
        mock_future.set_exception(TimeoutError("timed out"))

        with patch.object(
            self.analyzer._deepfake_executor, "submit", return_value=mock_future
        ):
            res = self.analyzer._analyze_deepfake_threat(
                "video.mp4", b"bytes", "video/mp4"
            )
            self.assertEqual(res["score"], 0.0)
            self.assertEqual(res["indicators"], [])
            self.assertIn(
                "Deepfake analysis timed out: video.mp4", res["errors"]
            )

    def test_analyze_deepfake_threat_exception(self):
        """Test _analyze_deepfake_threat handles unexpected exceptions."""
        mock_future = Future()
        mock_future.set_exception(RuntimeError("OpenCV failure"))

        with patch.object(
            self.analyzer._deepfake_executor, "submit", return_value=mock_future
        ):
            res = self.analyzer._analyze_deepfake_threat(
                "video.mp4", b"bytes", "video/mp4"
            )
            self.assertEqual(res["score"], 0.0)
            self.assertEqual(res["indicators"], [])
            self.assertEqual(res["errors"], [])

    def test_check_deepfake_indicators_non_media(self):
        """Test _check_deepfake_indicators ignores non-media files."""
        score, indicators = self.analyzer._check_deepfake_indicators(
            "doc.pdf", b"pdf data", "application/pdf"
        )
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])

    def test_check_deepfake_indicators_suspicious_small_video(self):
        """Test small video size triggers heuristic indicator."""
        small_data = b"small video"
        self.config.deepfake_detection_enabled = False

        score, indicators = self.analyzer._check_deepfake_indicators(
            "short.mp4", small_data, "video/mp4"
        )
        self.assertEqual(score, 0.5)
        self.assertIn("Suspicious video size: short.mp4", indicators)

    def test_check_deepfake_indicators_extract_frames_none(self):
        """Test frame extraction failure logs warning and returns base score."""
        with (
            patch.object(
                self.analyzer, "_extract_frames_from_video", return_value=[]
            ),
            patch.object(self.analyzer.logger, "warning") as mock_warn,
        ):
            score, indicators = self.analyzer._check_deepfake_indicators(
                "video.mp4", b"X" * (150 * 1024), "video/mp4"
            )
            self.assertEqual(score, 0.0)
            self.assertEqual(indicators, [])
            mock_warn.assert_called_once()
            self.assertIn("Could not extract frames", mock_warn.call_args[0][0])

    def test_check_deepfake_indicators_with_frames(self):
        """Test successful frame extraction delegates to _analyze_video_frames."""
        with (
            patch.object(
                self.analyzer,
                "_extract_frames_from_video",
                return_value=["frame1", "frame2"],
            ),
            patch.object(
                self.analyzer,
                "_analyze_video_frames",
                return_value=(3.0, ["deepfake detected"]),
            ),
        ):
            score, indicators = self.analyzer._check_deepfake_indicators(
                "sample.mp4", b"X" * (200 * 1024), "video/mp4"
            )
            self.assertEqual(score, 3.0)
            self.assertIn("deepfake detected", indicators)

    def test_check_deepfake_indicators_exception_caught(self):
        """Test exceptions in deepfake analysis are caught and logged."""
        with (
            patch.object(
                self.analyzer,
                "_extract_frames_from_video",
                side_effect=OSError("Disk failure"),
            ),
            patch.object(self.analyzer.logger, "error") as mock_error,
        ):
            score, indicators = self.analyzer._check_deepfake_indicators(
                "sample.mp4", b"X" * (200 * 1024), "video/mp4"
            )
            self.assertEqual(score, 0.0)
            self.assertEqual(indicators, [])
            mock_error.assert_called_once()
            self.assertIn(
                "Error during deepfake analysis", mock_error.call_args[0][0]
            )

    def test_forwarder_methods(self):
        """Test helper forwarder methods to ensure coverage of delegated calls."""
        with patch("src.modules.media_deepfake._check_audio_visual_sync", return_value=(0.0, [])) as mock_av:
            res = self.analyzer._check_audio_visual_sync("temp.mp4")
            mock_av.assert_called_once_with(self.analyzer, "temp.mp4")
            self.assertEqual(res, (0.0, []))

        with patch("src.modules.media_deepfake._run_deepfake_model", return_value=(0.0, [])) as mock_df:
            res = self.analyzer._run_deepfake_model("temp.mp4", [])
            mock_df.assert_called_once_with(self.analyzer, "temp.mp4", [])
            self.assertEqual(res, (0.0, []))

    def test_calculate_risk_level_cases(self):
        """Test risk levels across score ranges."""
        cases = [
            RiskTestCase(score=0.0, expected_risk="low"),
            RiskTestCase(score=1.9, expected_risk="low"),
            RiskTestCase(score=2.0, expected_risk="medium"),
            RiskTestCase(score=4.9, expected_risk="medium"),
            RiskTestCase(score=5.0, expected_risk="high"),
            RiskTestCase(score=10.0, expected_risk="high"),
        ]
        for case in cases:
            risk = self.analyzer._calculate_risk_level(case.score)
            self.assertEqual(risk, case.expected_risk)

    def test_shutdown_idempotent(self):
        """Test shutdown terminates thread pools cleanly."""
        self.analyzer.shutdown()
        # Verify executors are shut down
        self.assertTrue(self.analyzer._deepfake_executor._shutdown)
        self.assertTrue(self.analyzer._attachment_executor._shutdown)


if __name__ == "__main__":
    unittest.main()
