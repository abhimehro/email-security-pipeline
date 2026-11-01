import concurrent.futures
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


def build_email(attachments=None):
    return EmailData(
        message_id="msg-101",
        subject="Report",
        sender="sender@corp.local",
        recipient="recipient@corp.local",
        date=datetime.now(),
        body_text="Summary text",
        body_html="",
        headers={},
        attachments=attachments or [],
        raw_email=None,
        account_email="recipient@corp.local",
        folder="INBOX",
    )


def test_result_dataclass():
    res = MediaAnalysisResult(
        threat_score=2.0,
        suspicious_attachments=["warn.zip"],
        file_type_warnings=["Warning: bad extension"],
        size_anomalies=["Size exceeds 25MB"],
        potential_deepfakes=["Artifact detected"],
        risk_level="medium",
    )
    assert res.threat_score == 2.0
    assert res.suspicious_attachments == ["warn.zip"]
    assert res.file_type_warnings == ["Warning: bad extension"]
    assert res.size_anomalies == ["Size exceeds 25MB"]
    assert res.potential_deepfakes == ["Artifact detected"]
    assert res.risk_level == "medium"


def test_disabled_media_inspection(analyzer):
    analyzer.config.check_media_attachments = False
    payload = [
        {
            "filename": "payload.exe",
            "content_type": "application/octet-stream",
            "size": 512,
            "data": b"MZ\x90",
            "truncated": False,
        }
    ]
    res = analyzer.analyze(build_email(payload))
    assert res.threat_score == 0.0
    assert res.risk_level == "low"
    assert not res.suspicious_attachments


def test_unattached_email(analyzer):
    res = analyzer.analyze(build_email([]))
    assert res.threat_score == 0.0
    assert res.risk_level == "low"
    assert res.suspicious_attachments == []


def test_standard_pdf(analyzer):
    doc_bytes = b"%PDF-1.7 header and body"
    payload = [
        {
            "filename": "doc.pdf",
            "content_type": "application/pdf",
            "size": len(doc_bytes),
            "data": doc_bytes,
            "truncated": False,
        }
    ]
    res = analyzer.analyze(build_email(payload))
    assert res.threat_score == 0.0
    assert res.risk_level == "low"
    assert res.file_type_warnings == []


def test_executable_flagged(analyzer):
    payload = [
        {
            "filename": "installer.exe",
            "content_type": "application/x-msdownload",
            "size": 1024,
            "data": b"MZ\x00\x00data",
            "truncated": False,
        }
    ]
    res = analyzer.analyze(build_email(payload))
    assert res.threat_score >= 5.0
    assert res.risk_level == "high"
    assert any("Dangerous file type" in w for w in res.file_type_warnings)


def test_dual_extension(analyzer):
    payload = [
        {
            "filename": "doc.pdf.exe",
            "content_type": "application/x-msdownload",
            "size": 500,
            "data": b"MZ",
            "truncated": False,
        }
    ]
    res = analyzer.analyze(build_email(payload))
    assert res.threat_score >= 5.0
    assert any("Multiple extensions detected" in w for w in res.file_type_warnings)


def test_masquerading_executable(analyzer):
    payload = [
        {
            "filename": "photo.png",
            "content_type": "image/png",
            "size": 100,
            "data": b"MZ\x90\x00notapng",
            "truncated": False,
        }
    ]
    res = analyzer.analyze(build_email(payload))
    assert res.threat_score >= 5.0
    assert any(
        "Executable disguised as another file type" in w
        for w in res.suspicious_attachments
    )


def test_large_and_truncated_payload(analyzer):
    limit_mb = analyzer.MAX_ATTACHMENT_SIZE_MB
    payload = [
        {
            "filename": "backup.iso",
            "content_type": "application/octet-stream",
            "size": (limit_mb + 2) * 1024 * 1024,
            "data": b"content",
            "truncated": True,
        }
    ]
    res = analyzer.analyze(build_email(payload))
    assert any("Attachment truncated for scanning" in a for a in res.size_anomalies)
    assert any("Unusually large attachment" in a for a in res.size_anomalies)


def test_deepfake_pipeline(analyzer):
    with patch.object(
        analyzer,
        "_check_deepfake_indicators",
        return_value=(3.0, ["Inconsistent optical flow"]),
    ) as mock_deepfake:
        payload = [
            {
                "filename": "clip.mp4",
                "content_type": "video/mp4",
                "size": 4096,
                "data": b"\x00\x00\x00\x18ftypmp42",
                "truncated": False,
            }
        ]
        res = analyzer.analyze(build_email(payload))
        mock_deepfake.assert_called_once()
        assert "Inconsistent optical flow" in res.potential_deepfakes
        assert res.threat_score >= 3.0


def test_deepfake_stop_on_critical_score(analyzer):
    payload = [
        {
            "filename": "malware.exe",
            "content_type": "application/x-msdownload",
            "size": 1024,
            "data": b"MZ",
            "truncated": False,
        },
        {
            "filename": "clip.mp4",
            "content_type": "video/mp4",
            "size": 2048,
            "data": b"\x00\x00\x00\x18ftypmp42",
            "truncated": False,
        },
    ]
    with patch.object(analyzer, "_check_deepfake_indicators") as mock_chk:
        res = analyzer.analyze(build_email(payload))
        assert res.threat_score >= 5.0
        mock_chk.assert_not_called()


def test_deepfake_timeout_behavior(analyzer):
    future = MagicMock()
    future.result.side_effect = concurrent.futures.TimeoutError("Exceeded")
    with patch.object(analyzer._deepfake_executor, "submit", return_value=future):
        out = analyzer._analyze_deepfake_threat("video.mp4", b"data", "video/mp4")
        assert out["score"] == 0.0
        assert any("Deepfake analysis timed out" in err for err in out["errors"])


def test_deepfake_exception_behavior(analyzer):
    future = MagicMock()
    future.result.side_effect = RuntimeError("Processing failure")
    with patch.object(analyzer._deepfake_executor, "submit", return_value=future):
        out = analyzer._analyze_deepfake_threat("video.mp4", b"data", "video/mp4")
        assert out["score"] == 0.0
        assert out["indicators"] == []


def test_shutdown_lifecycle(analyzer):
    assert not analyzer._deepfake_executor._shutdown
    assert not analyzer._attachment_executor._shutdown
    analyzer.shutdown()
    assert analyzer._deepfake_executor._shutdown
    assert analyzer._attachment_executor._shutdown
