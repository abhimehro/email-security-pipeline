"""Unit tests for MediaAuthenticityAnalyzer."""

from datetime import datetime
from typing import NamedTuple
from unittest.mock import MagicMock, patch

import pytest

from src.modules.email_ingestion import EmailData
from src.modules.media_analyzer import MediaAuthenticityAnalyzer


class RiskScenario(NamedTuple):
    """Scenario parameters for testing risk level threshold boundaries."""

    score: float
    expected_risk: str


class MockAnalysisConfig:
    """Mock configuration for MediaAuthenticityAnalyzer tests."""

    def __init__(
        self,
        check_media_attachments: bool = True,
        deepfake_detection_enabled: bool = False,
        media_analysis_timeout: float = 2.0,
    ):
        """Initialize mock analysis configuration."""
        self.check_media_attachments = check_media_attachments
        self.deepfake_detection_enabled = deepfake_detection_enabled
        self.media_analysis_timeout = media_analysis_timeout


@pytest.fixture
def mock_config():
    """Provide a default MockAnalysisConfig fixture."""
    return MockAnalysisConfig()


@pytest.fixture
def analyzer(mock_config):
    """Provide a MediaAuthenticityAnalyzer instance and ensure cleanup on teardown."""
    inst = MediaAuthenticityAnalyzer(mock_config)
    yield inst
    inst.shutdown()


def _create_email(attachments=None) -> EmailData:
    """Create an EmailData instance for testing."""
    return EmailData(
        message_id="msg-1",
        subject="Test Subject",
        sender="sender@example.com",
        recipient="user@example.com",
        date=datetime.now(),
        body_text="Body content",
        body_html="",
        headers={},
        attachments=attachments or [],
        raw_email=None,
        account_email="user@example.com",
        folder="INBOX",
    )


def test_analyze_disabled_or_empty_attachments(analyzer):
    """Test fast return when media check is disabled or attachments list is empty."""
    # Empty attachments with check enabled
    email_empty = _create_email(attachments=[])
    res_empty = analyzer.analyze(email_empty)
    assert res_empty.threat_score == 0.0
    assert res_empty.risk_level == "low"
    assert res_empty.suspicious_attachments == []

    # Attachments present but check_media_attachments is disabled
    analyzer.config.check_media_attachments = False
    email_with_att = _create_email(
        attachments=[
            {
                "filename": "document.pdf",
                "content_type": "application/pdf",
                "size": 1024,
                "data": b"%PDF-1.4...",
                "truncated": False,
            }
        ]
    )
    res_disabled = analyzer.analyze(email_with_att)
    assert res_disabled.threat_score == 0.0
    assert res_disabled.risk_level == "low"


def test_analyze_clean_attachment_happy_path(analyzer):
    """Test analyze with a benign attachment produces low risk and 0 score."""
    email = _create_email(
        attachments=[
            {
                "filename": "sample.pdf",
                "content_type": "application/pdf",
                "size": 1024,
                "data": b"%PDF-1.4 clean pdf test data",
                "truncated": False,
            }
        ]
    )
    result = analyzer.analyze(email)
    assert result.threat_score == 0.0
    assert result.risk_level == "low"
    assert not result.file_type_warnings
    assert not result.suspicious_attachments


def test_analyze_early_cutoff_threshold(analyzer):
    """Test analyze sets shared stop_deepfake when score exceeds threshold >= 5.0."""
    email = _create_email(
        attachments=[
            {
                "filename": "malware.exe",
                "content_type": "application/x-msdownload",
                "size": 1024,
                "data": b"MZ...",
                "truncated": False,
            },
            {
                "filename": "video.mp4",
                "content_type": "video/mp4",
                "size": 2048,
                "data": b"....ftypmp42....",
                "truncated": False,
            },
        ]
    )
    analyzer.config.deepfake_detection_enabled = True

    with patch.object(
        analyzer,
        "_analyze_deepfake_threat",
        return_value={"score": 0.0, "indicators": [], "errors": []},
    ) as mock_deepfake:
        result = analyzer.analyze(email)
        assert result.threat_score >= 5.0
        assert result.risk_level == "high"
        # Since malware.exe has score 5.0, subsequent attachments have stop_deepfake flag set
        # so deepfake threat analysis should not be performed for video.mp4
        mock_deepfake.assert_not_called()


def test_process_attachment_parallel_flag_conditions(analyzer):
    """Test _process_attachment_parallel branches for disabled and stop states."""
    attachment = {
        "filename": "clip.mp4",
        "content_type": "video/mp4",
        "size": 2048,
        "data": b"....ftypmp42....",
        "truncated": False,
    }

    # Case 1: deepfake_detection_enabled = False
    analyzer.config.deepfake_detection_enabled = False
    meta, deepfake = analyzer._process_attachment_parallel(
        attachment, {"stop_deepfake": False}
    )
    assert deepfake is None

    # Case 2: shared stop_deepfake is True
    analyzer.config.deepfake_detection_enabled = True
    meta, deepfake = analyzer._process_attachment_parallel(
        attachment, {"stop_deepfake": True}
    )
    assert deepfake is None

    # Case 3: meta score >= 5.0 suppresses deepfake analysis
    with patch.object(
        analyzer,
        "_analyze_attachment_metadata",
        return_value={
            "score": 5.0,
            "size_anomalies": [],
            "file_type_warnings": [],
            "suspicious_attachments": [],
        },
    ):
        meta, deepfake = analyzer._process_attachment_parallel(
            attachment, {"stop_deepfake": False}
        )
        assert deepfake is None


def test_analyze_deepfake_threat_exception_handling(analyzer):
    """Test _analyze_deepfake_threat catches exceptions and logs errors."""
    mock_executor = MagicMock()
    mock_executor.submit.side_effect = RuntimeError("Executor submission failed")
    analyzer._deepfake_executor = mock_executor

    result = analyzer._analyze_deepfake_threat("video.mp4", b"data", "video/mp4")
    assert result["score"] == 0.0
    assert result["indicators"] == []
    assert result["errors"] == []


def test_check_deepfake_indicators_non_media(analyzer):
    """Test _check_deepfake_indicators ignores non-media files."""
    score, indicators = analyzer._check_deepfake_indicators(
        "document.txt", b"text data", "text/plain"
    )
    assert score == 0.0
    assert indicators == []


def test_check_deepfake_indicators_small_video_heuristic(analyzer):
    """Test small video size anomaly under 100KB adds 0.5 score."""
    analyzer.config.deepfake_detection_enabled = False
    small_data = b"x" * 1024  # 1KB < 100KB
    score, indicators = analyzer._check_deepfake_indicators(
        "sample.mp4", small_data, "video/mp4"
    )
    assert score == 0.5
    assert any("Suspicious video size: sample.mp4" in ind for ind in indicators)


@pytest.mark.parametrize(
    "scenario",
    [
        RiskScenario(score=0.0, expected_risk="low"),
        RiskScenario(score=1.9, expected_risk="low"),
        RiskScenario(score=2.0, expected_risk="medium"),
        RiskScenario(score=4.9, expected_risk="medium"),
        RiskScenario(score=5.0, expected_risk="high"),
        RiskScenario(score=10.0, expected_risk="high"),
    ],
)
def test_calculate_risk_level_boundaries(analyzer, scenario: RiskScenario):
    """Test risk level calculation conforms to defined score thresholds."""
    assert analyzer._calculate_risk_level(scenario.score) == scenario.expected_risk


def test_shutdown_cleanup():
    """Test shutdown terminates thread pools cleanly."""
    config = MockAnalysisConfig()
    analyzer = MediaAuthenticityAnalyzer(config)
    deepfake_exec = analyzer._deepfake_executor
    attachment_exec = analyzer._attachment_executor

    assert not deepfake_exec._shutdown
    assert not attachment_exec._shutdown

    analyzer.shutdown()

    assert deepfake_exec._shutdown
    assert attachment_exec._shutdown
