"""Unit tests for MediaAuthenticityAnalyzer in src/modules/media_analyzer.py."""

from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.modules.email_data import EmailData
from src.modules.media_analyzer import (
    MediaAnalysisResult,
    MediaAuthenticityAnalyzer,
)


class MockMediaConfig:
    """Mock configuration for media analysis tests."""

    def __init__(self):
        """Initialize mock configuration attributes."""
        self.check_media_attachments = True
        self.deepfake_detection_enabled = False
        self.media_analysis_timeout = 2


@pytest.fixture
def media_config():
    """Fixture providing a fresh mock media configuration."""
    return MockMediaConfig()


@pytest.fixture
def media_analyzer(media_config):
    """Fixture providing a MediaAuthenticityAnalyzer instance and ensuring cleanup."""
    analyzer = MediaAuthenticityAnalyzer(media_config)
    yield analyzer
    analyzer.shutdown()


def create_email_with_attachments(attachments):
    """Create an EmailData container with specified attachments."""
    return EmailData(
        message_id="msg-media-101",
        subject="Important Media Update",
        sender="media-test@example.com",
        recipient="security@example.com",
        date=datetime(2025, 1, 15, 12, 0, 0),
        body_text="Please review the attached media documents.",
        body_html="<p>Please review the attached media documents.</p>",
        headers={},
        attachments=attachments,
        raw_email=None,
        account_email="security@example.com",
        folder="INBOX",
    )


def test_media_analyzer_initialization(media_config):
    """Test analyzer initialization and executor setup."""
    analyzer = MediaAuthenticityAnalyzer(media_config)
    try:
        assert analyzer.config == media_config
        assert analyzer.logger.name == "MediaAuthenticityAnalyzer"
        assert analyzer.face_cascade is None
        assert analyzer._deepfake_executor is not None
        assert analyzer._attachment_executor is not None
    finally:
        analyzer.shutdown()


def test_media_analyzer_shutdown(media_config):
    """Test shutdown cleans up ThreadPoolExecutor resources without errors."""
    analyzer = MediaAuthenticityAnalyzer(media_config)
    analyzer.shutdown()
    # Calling shutdown twice should be safe and idempotent
    analyzer.shutdown()


def test_analyze_disabled_or_empty_attachments(media_analyzer, media_config):
    """Test early return when attachments are empty or media analysis is disabled."""
    empty_email = create_email_with_attachments([])
    result_empty = media_analyzer.analyze(empty_email)
    assert isinstance(result_empty, MediaAnalysisResult)
    assert result_empty.threat_score == 0.0
    assert result_empty.risk_level == "low"
    assert result_empty.suspicious_attachments == []
    assert result_empty.file_type_warnings == []
    assert result_empty.size_anomalies == []
    assert result_empty.potential_deepfakes == []

    media_config.check_media_attachments = False
    attachment_email = create_email_with_attachments(
        [
            {
                "filename": "document.pdf",
                "content_type": "application/pdf",
                "size": 100,
                "data": b"%PDF-1.4 sample",
                "truncated": False,
            }
        ]
    )
    result_disabled = media_analyzer.analyze(attachment_email)
    assert result_disabled.threat_score == 0.0
    assert result_disabled.risk_level == "low"


def test_analyze_clean_attachments(media_analyzer):
    """Test analyzing valid, benign attachments."""
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
    email = create_email_with_attachments(
        [
            {
                "filename": "screenshot.png",
                "content_type": "image/png",
                "size": len(png_data),
                "data": png_data,
                "truncated": False,
            }
        ]
    )
    result = media_analyzer.analyze(email)
    assert result.threat_score == 0.0
    assert result.risk_level == "low"
    assert result.suspicious_attachments == []
    assert result.file_type_warnings == []
    assert result.size_anomalies == []


@pytest.mark.parametrize(
    "filename,file_data",
    [
        ("script.bat", b"echo malicious"),
        ("payload.pdf.exe", b"MZ\x90\x00"),
        ("install.scr", b"MZ\x90\x00"),
    ],
)
def test_analyze_dangerous_attachments(media_analyzer, filename, file_data):
    """Test detection and high scoring of dangerous file extensions."""
    email = create_email_with_attachments(
        [
            {
                "filename": filename,
                "content_type": "application/octet-stream",
                "size": len(file_data),
                "data": file_data,
                "truncated": False,
            }
        ]
    )
    result = media_analyzer.analyze(email)
    assert result.threat_score >= 5.0
    assert result.risk_level == "high"
    assert len(result.file_type_warnings) > 0


def test_analyze_content_type_mismatch(media_analyzer):
    """Test flagging content type mismatches and invalid signatures."""
    # A file with .png extension containing exe magic bytes
    disguised_exe = b"MZ" + b"\x00" * 100
    email = create_email_with_attachments(
        [
            {
                "filename": "fake_image.png",
                "content_type": "image/png",
                "size": len(disguised_exe),
                "data": disguised_exe,
                "truncated": False,
            }
        ]
    )
    result = media_analyzer.analyze(email)
    assert result.threat_score >= 5.0
    assert any("Executable disguised" in item for item in result.suspicious_attachments)


def test_analyze_size_anomalies(media_analyzer):
    """Test detection of truncated attachments, oversized files, and undersized media."""
    small_video = b"\x00\x00\x00\x20ftypisom"  # 12 bytes (< 1024 bytes threshold)
    large_size = (MediaAuthenticityAnalyzer.MAX_ATTACHMENT_SIZE_MB + 5) * 1024 * 1024
    email = create_email_with_attachments(
        [
            {
                "filename": "truncated.txt",
                "content_type": "text/plain",
                "size": 50,
                "data": b"truncated data",
                "truncated": True,
            },
            {
                "filename": "huge.dat",
                "content_type": "application/octet-stream",
                "size": large_size,
                "data": b"",
                "truncated": False,
            },
            {
                "filename": "tiny.mp4",
                "content_type": "video/mp4",
                "size": len(small_video),
                "data": small_video,
                "truncated": False,
            },
        ]
    )
    result = media_analyzer.analyze(email)
    assert len(result.size_anomalies) >= 3
    anomalies_str = " ".join(result.size_anomalies)
    assert "Attachment truncated" in anomalies_str
    assert "Unusually large attachment" in anomalies_str
    assert "Suspiciously small media file" in anomalies_str


def test_analyze_early_stop_threshold(media_analyzer, media_config):
    """Test threshold shortcutting when threat score reaches 5.0."""
    media_config.deepfake_detection_enabled = True
    dangerous_data = b"MZ\x90\x00"
    email = create_email_with_attachments(
        [
            {
                "filename": "malware.exe",
                "content_type": "application/x-msdownload",
                "size": len(dangerous_data),
                "data": dangerous_data,
                "truncated": False,
            },
            {
                "filename": "sample.mp4",
                "content_type": "video/mp4",
                "size": 2048,
                "data": b"\x00\x00\x00\x20ftypisom" + b"\x00" * 2036,
                "truncated": False,
            },
        ]
    )

    with patch.object(
        media_analyzer,
        "_analyze_deepfake_threat",
        wraps=media_analyzer._analyze_deepfake_threat,
    ) as mock_deepfake:
        result = media_analyzer.analyze(email)
        assert result.threat_score >= 5.0
        assert result.risk_level == "high"
        # Since the first attachment triggered score >= 5.0, deepfake analysis should be skipped
        assert mock_deepfake.call_count == 0


def test_analyze_deepfake_flow(media_analyzer, media_config):
    """Test successful deepfake detection execution."""
    media_config.deepfake_detection_enabled = True
    valid_mp4_data = b"\x00\x00\x00\x20ftypisom" + b"\x00" * 2000
    email = create_email_with_attachments(
        [
            {
                "filename": "interview.mp4",
                "content_type": "video/mp4",
                "size": len(valid_mp4_data),
                "data": valid_mp4_data,
                "truncated": False,
            }
        ]
    )

    mock_indicators = (3.5, ["Facial warping detected in frames"])
    with patch.object(
        media_analyzer, "_check_deepfake_indicators", return_value=mock_indicators
    ):
        result = media_analyzer.analyze(email)
        assert result.threat_score >= 3.5
        assert "Facial warping detected in frames" in result.potential_deepfakes
        assert result.risk_level == "medium"


def test_analyze_deepfake_timeout(media_analyzer, media_config):
    """Test handling of deepfake timeout during execution."""
    media_config.deepfake_detection_enabled = True
    valid_mp4_data = b"\x00\x00\x00\x20ftypisom" + b"\x00" * 2000
    email = create_email_with_attachments(
        [
            {
                "filename": "clip.mp4",
                "content_type": "video/mp4",
                "size": len(valid_mp4_data),
                "data": valid_mp4_data,
                "truncated": False,
            }
        ]
    )

    mock_future = MagicMock()
    mock_future.result.side_effect = FuturesTimeoutError("Simulated timeout")
    with patch.object(media_analyzer._deepfake_executor, "submit", return_value=mock_future):
        result = media_analyzer.analyze(email)
        assert any("timed out" in err for err in result.size_anomalies)


@pytest.mark.parametrize(
    "score,expected_risk",
    [
        (0.0, "low"),
        (1.9, "low"),
        (2.0, "medium"),
        (4.9, "medium"),
        (5.0, "high"),
        (10.0, "high"),
    ],
)
def test_risk_level_calculation(media_analyzer, score, expected_risk):
    """Test risk level thresholds mapping for media analysis scores."""
    assert media_analyzer._calculate_risk_level(score) == expected_risk
