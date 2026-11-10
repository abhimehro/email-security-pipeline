"""Unit tests for MediaAuthenticityAnalyzer and MediaAnalysisResult.

Verifies lifecycle, analysis orchestration, parallel processing,
deepfake indicator heuristics, and risk level calculations.
"""

from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import NamedTuple
from unittest.mock import MagicMock, patch

import pytest

from src.modules.email_ingestion import EmailData
from src.modules.media_analyzer import (
    MediaAnalysisResult,
    MediaAuthenticityAnalyzer,
)
from src.utils.config import AnalysisConfig


class RiskBoundaryCase(NamedTuple):
    """Encapsulates score and expected risk level for boundary checks."""

    score: float
    expected_risk: str


class ProcessAttachmentCase(NamedTuple):
    """Encapsulates inputs and expected deepfake execution state."""

    deepfake_enabled: bool
    stop_deepfake: bool
    meta_score: float
    should_run_deepfake: bool


def _make_config(**kwargs) -> AnalysisConfig:
    """Build AnalysisConfig with default test values."""
    defaults = {
        "spam_threshold": 5.0,
        "spam_check_headers": True,
        "spam_check_urls": True,
        "nlp_model": "test",
        "nlp_model_revision": "main",
        "nlp_threshold": 0.7,
        "nlp_batch_size": 8,
        "check_social_engineering": True,
        "check_urgency_markers": True,
        "check_authority_impersonation": True,
        "check_media_attachments": True,
        "deepfake_detection_enabled": True,
        "media_analysis_timeout": 5,
        "deepfake_provider": "simulator",
        "deepfake_api_key": None,
        "deepfake_api_url": None,
        "deepfake_model_path": None,
    }
    defaults.update(kwargs)
    return AnalysisConfig(**defaults)


def _make_email_data(attachments=None) -> EmailData:
    """Build EmailData with default test values."""
    return EmailData(
        message_id="msg-123",
        subject="Test Media",
        sender="sender@example.com",
        recipient="recipient@example.com",
        date=datetime.now(),
        body_text="Test email body",
        body_html="<p>Test email body</p>",
        headers={},
        attachments=attachments or [],
        raw_email=None,
        account_email="me@example.com",
        folder="INBOX",
    )


@pytest.fixture
def analyzer():
    """Yield active MediaAuthenticityAnalyzer instance and shutdown after."""
    config = _make_config()
    instance = MediaAuthenticityAnalyzer(config)
    yield instance
    instance.shutdown()


def test_media_analysis_result_dataclass():
    """Verify initialization and fields of MediaAnalysisResult."""
    result = MediaAnalysisResult(
        threat_score=3.5,
        suspicious_attachments=["attachment1.exe"],
        file_type_warnings=["Warning: executable"],
        size_anomalies=["Size too large"],
        potential_deepfakes=["Audio desync"],
        risk_level="medium",
    )

    assert result.threat_score == 3.5
    assert result.suspicious_attachments == ["attachment1.exe"]
    assert result.file_type_warnings == ["Warning: executable"]
    assert result.size_anomalies == ["Size too large"]
    assert result.potential_deepfakes == ["Audio desync"]
    assert result.risk_level == "medium"


def test_analyzer_init_and_shutdown():
    """Verify analyzer initializes thread pools and shuts them down properly."""
    config = _make_config()
    analyzer_inst = MediaAuthenticityAnalyzer(config)

    assert hasattr(analyzer_inst, "_deepfake_executor")
    assert hasattr(analyzer_inst, "_attachment_executor")
    assert analyzer_inst.face_cascade is None

    # Shutdown should execute without error
    analyzer_inst.shutdown()


@pytest.mark.parametrize(
    "check_attachments,attachments",
    [
        (False, [{"filename": "test.png", "data": b"123"}]),
        (True, []),
        (False, []),
    ],
)
def test_analyze_fast_path_empty_or_disabled(check_attachments, attachments):
    """Verify fast path returns zero score when disabled or empty."""
    config = _make_config(check_media_attachments=check_attachments)
    analyzer_inst = MediaAuthenticityAnalyzer(config)
    try:
        email_data = _make_email_data(attachments=attachments)
        result = analyzer_inst.analyze(email_data)

        assert result.threat_score == 0.0
        assert result.risk_level == "low"
        assert result.suspicious_attachments == []
        assert result.file_type_warnings == []
        assert result.size_anomalies == []
        assert result.potential_deepfakes == []
    finally:
        analyzer_inst.shutdown()


def test_analyze_clean_attachments(analyzer):
    """Verify clean attachments result in low risk score and no warnings."""
    clean_attachment = {
        "filename": "document.txt",
        "data": b"Hello world! This is a benign text file.",
        "size": 38,
        "content_type": "text/plain",
    }
    email_data = _make_email_data(attachments=[clean_attachment])
    result = analyzer.analyze(email_data)

    assert result.threat_score == 0.0
    assert result.risk_level == "low"
    assert result.file_type_warnings == []
    assert result.potential_deepfakes == []


def test_analyze_threshold_early_termination(analyzer):
    """Verify shared_state halts deepfake analysis once threat score >= 5.0."""
    high_threat_att = {
        "filename": "payload1.exe",
        "data": b"MZ" + b"\x00" * 200,
        "size": 202,
        "content_type": "application/x-msdownload",
    }
    video_att = {
        "filename": "video.mp4",
        "data": b"data",
        "size": 4,
        "content_type": "video/mp4",
    }
    email_data = _make_email_data(attachments=[high_threat_att, video_att])

    with patch.object(
        analyzer, "_analyze_deepfake_threat", wraps=analyzer._analyze_deepfake_threat
    ) as mock_deepfake:
        result = analyzer.analyze(email_data)

        assert result.threat_score >= 5.0
        assert result.risk_level == "high"
        # Deepfake analysis should be bypassed for video because threshold is exceeded
        mock_deepfake.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        ProcessAttachmentCase(
            deepfake_enabled=False,
            stop_deepfake=False,
            meta_score=0.0,
            should_run_deepfake=False,
        ),
        ProcessAttachmentCase(
            deepfake_enabled=True,
            stop_deepfake=True,
            meta_score=0.0,
            should_run_deepfake=False,
        ),
        ProcessAttachmentCase(
            deepfake_enabled=True,
            stop_deepfake=False,
            meta_score=5.5,
            should_run_deepfake=False,
        ),
        ProcessAttachmentCase(
            deepfake_enabled=True,
            stop_deepfake=False,
            meta_score=1.0,
            should_run_deepfake=True,
        ),
    ],
)
def test_process_attachment_parallel_guards(case):
    """Verify conditional guards controlling deepfake execution in parallel worker."""
    config = _make_config(deepfake_detection_enabled=case.deepfake_enabled)
    analyzer_inst = MediaAuthenticityAnalyzer(config)
    try:
        shared_state = {"stop_deepfake": case.stop_deepfake}
        attachment = {
            "filename": "clip.mp4",
            "data": b"\x00" * 50,
            "content_type": "video/mp4",
        }

        mock_meta = {
            "score": case.meta_score,
            "suspicious_attachments": [],
            "file_type_warnings": [],
            "size_anomalies": [],
        }

        with (
            patch.object(
                analyzer_inst,
                "_analyze_attachment_metadata",
                return_value=mock_meta,
            ),
            patch.object(
                analyzer_inst,
                "_analyze_deepfake_threat",
                return_value={"score": 0.0, "indicators": [], "errors": []},
            ) as mock_threat,
        ):
            _, deepfake_res = analyzer_inst._process_attachment_parallel(
                attachment, shared_state
            )

            if case.should_run_deepfake:
                mock_threat.assert_called_once_with(
                    "clip.mp4", b"\x00" * 50, "video/mp4"
                )
                assert deepfake_res is not None
            else:
                mock_threat.assert_not_called()
                assert deepfake_res is None
    finally:
        analyzer_inst.shutdown()


def test_analyze_deepfake_threat_timeout(analyzer):
    """Verify TimeoutError in deepfake threat analysis is recorded in errors."""
    with patch.object(
        analyzer._deepfake_executor, "submit"
    ) as mock_submit:
        mock_future = MagicMock()
        mock_future.result.side_effect = FuturesTimeoutError()
        mock_submit.return_value = mock_future

        result = analyzer._analyze_deepfake_threat(
            "test.mp4", b"data", "video/mp4"
        )

        assert result["score"] == 0.0
        assert "Deepfake analysis timed out: test.mp4" in result["errors"]


def test_analyze_deepfake_threat_exception(analyzer):
    """Verify unexpected exceptions in _analyze_deepfake_threat are logged cleanly."""
    with patch.object(
        analyzer._deepfake_executor, "submit"
    ) as mock_submit:
        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("Executor failure")
        mock_submit.return_value = mock_future

        result = analyzer._analyze_deepfake_threat(
            "test.mp4", b"data", "video/mp4"
        )

        assert result["score"] == 0.0
        assert result["indicators"] == []


def test_check_deepfake_indicators_non_media(analyzer):
    """Verify non-media files immediately return 0 score and empty indicators."""
    score, indicators = analyzer._check_deepfake_indicators(
        "notes.txt", b"some plain text", "text/plain"
    )
    assert score == 0.0
    assert indicators == []


def test_check_deepfake_indicators_small_video_heuristic(analyzer):
    """Verify video files smaller than 100KB trigger suspicious size indicator."""
    config = _make_config(deepfake_detection_enabled=False)
    analyzer_inst = MediaAuthenticityAnalyzer(config)
    try:
        small_data = b"video data"
        score, indicators = analyzer_inst._check_deepfake_indicators(
            "clip.mp4", small_data, "video/mp4"
        )
        assert score == 0.5
        assert "Suspicious video size: clip.mp4" in indicators
    finally:
        analyzer_inst.shutdown()


def test_check_deepfake_indicators_video_frame_pipeline(analyzer):
    """Verify video frame extraction and video frame analysis interaction."""
    fake_frames = [MagicMock(), MagicMock()]
    with (
        patch.object(
            analyzer, "_extract_frames_from_video", return_value=fake_frames
        ),
        patch.object(
            analyzer,
            "_analyze_video_frames",
            return_value=(2.5, ["Facial anomaly detected"]),
        ),
    ):
        # Provide >100KB data so small video heuristic does not fire
        video_data = b"\x00" * (105 * 1024)
        score, indicators = analyzer._check_deepfake_indicators(
            "sample.mp4", video_data, "video/mp4"
        )

        assert score == 2.5
        assert "Facial anomaly detected" in indicators


def test_check_deepfake_indicators_no_frames_extracted(analyzer):
    """Verify logging and empty indicators when frame extraction yields no frames."""
    with patch.object(
        analyzer, "_extract_frames_from_video", return_value=[]
    ):
        video_data = b"\x00" * (105 * 1024)
        score, indicators = analyzer._check_deepfake_indicators(
            "corrupt.mp4", video_data, "video/mp4"
        )

        assert score == 0.0
        assert indicators == []


@pytest.mark.parametrize(
    "case",
    [
        RiskBoundaryCase(score=0.0, expected_risk="low"),
        RiskBoundaryCase(score=1.99, expected_risk="low"),
        RiskBoundaryCase(score=2.0, expected_risk="medium"),
        RiskBoundaryCase(score=4.99, expected_risk="medium"),
        RiskBoundaryCase(score=5.0, expected_risk="high"),
        RiskBoundaryCase(score=10.0, expected_risk="high"),
    ],
)
def test_calculate_risk_level_boundaries(analyzer, case):
    """Verify risk level calculations across low, medium, and high score boundaries."""
    risk = analyzer._calculate_risk_level(case.score)
    assert risk == case.expected_risk
