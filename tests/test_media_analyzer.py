"""Unit tests for media authenticity analyzer."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.modules.email_ingestion import EmailData
from src.modules.media_analyzer import MediaAnalysisResult, MediaAuthenticityAnalyzer


class DummyConfig:
    check_media_attachments = True
    deepfake_detection_enabled = True
    media_analysis_timeout = 5


@pytest.fixture
def analyzer():
    instance = MediaAuthenticityAnalyzer(DummyConfig())
    yield instance
    instance.shutdown()


def create_email_fixture(attachments):
    return EmailData(
        message_id="msg-101",
        subject="Report",
        sender="sender@corp.local",
        recipient="recipient@corp.local",
        date=datetime.now(),
        body_text="Summary text",
        body_html="",
        headers={},
        attachments=attachments,
        raw_email=None,
        account_email="recipient@corp.local",
        folder="INBOX",
    )


def test_result_dataclass():
    res = MediaAnalysisResult(1.0, ["a"], ["b"], ["c"], ["d"], "low")
    assert res.threat_score == 1.0
    assert res.risk_level == "low"


def test_disabled_media_inspection(analyzer):
    analyzer.config.check_media_attachments = False
    res = analyzer.analyze(create_email_fixture([]))
    assert res.threat_score == 0.0
    assert res.risk_level == "low"


def test_clean_pdf(analyzer):
    att = {
        "filename": "doc.pdf",
        "content_type": "application/pdf",
        "size": 24,
        "data": b"%PDF-1.7 header",
        "truncated": False,
    }
    res = analyzer.analyze(create_email_fixture([att]))
    assert res.threat_score == 0.0


def test_executable_warning(analyzer):
    att = {
        "filename": "test.exe",
        "content_type": "application/octet-stream",
        "size": 100,
        "data": b"MZ\x00",
        "truncated": False,
    }
    res = analyzer.analyze(create_email_fixture([att]))
    assert res.threat_score >= 5.0
    assert res.risk_level == "high"


def test_double_extension(analyzer):
    att = {
        "filename": "test.pdf.exe",
        "content_type": "application/octet-stream",
        "size": 100,
        "data": b"MZ\x00",
        "truncated": False,
    }
    res = analyzer.analyze(create_email_fixture([att]))
    assert res.threat_score >= 5.0


def test_deepfake_flow(analyzer):
    with patch.object(analyzer, "_check_deepfake_indicators", return_value=(3.0, ["deepfake detected"])):
        att = {
            "filename": "video.mp4",
            "content_type": "video/mp4",
            "size": 2048,
            "data": b"\x00\x00\x00\x18ftypmp42",
            "truncated": False,
        }
        res = analyzer.analyze(create_email_fixture([att]))
        assert res.threat_score >= 3.0
        assert "deepfake detected" in res.potential_deepfakes


def test_deepfake_threshold_cutoff(analyzer):
    with patch.object(analyzer, "_check_deepfake_indicators") as mock_chk:
        atts = [
            {"filename": "bad.exe", "content_type": "app/bin", "size": 100, "data": b"MZ", "truncated": False},
            {"filename": "video.mp4", "content_type": "video/mp4", "size": 200, "data": b"ftyp", "truncated": False},
        ]
        res = analyzer.analyze(create_email_fixture(atts))
        assert res.threat_score >= 5.0
        mock_chk.assert_not_called()


def test_analyzer_shutdown(analyzer):
    analyzer.shutdown()
    assert analyzer._deepfake_executor._shutdown
