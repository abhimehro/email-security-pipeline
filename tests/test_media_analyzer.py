"""Unit tests for MediaAuthenticityAnalyzer core behavior and result schema."""

from unittest.mock import MagicMock, patch

from src.modules.media_analyzer import MediaAnalysisResult, MediaAuthenticityAnalyzer


def test_media_analysis_result_attributes():
    payload = {
        "threat_score": 3.5,
        "suspicious_attachments": ["sample.zip"],
        "file_type_warnings": ["disguised file"],
        "size_anomalies": ["oversized"],
        "potential_deepfakes": ["framerate jitter"],
        "risk_level": "medium",
    }
    result = MediaAnalysisResult(**payload)
    assert result.threat_score == 3.5
    assert result.risk_level == "medium"
    assert result.potential_deepfakes == ["framerate jitter"]


def test_analyze_when_media_check_turned_off():
    cfg = MagicMock(check_media_attachments=False)
    analyzer = MediaAuthenticityAnalyzer(cfg)
    fake_mail = MagicMock(attachments=[{"filename": "malware.exe"}])

    res = analyzer.analyze(fake_mail)
    analyzer.shutdown()

    assert res.threat_score == 0.0
    assert res.risk_level == "low"
    assert not res.suspicious_attachments


def test_analyze_without_any_attachments():
    cfg = MagicMock(check_media_attachments=True)
    analyzer = MediaAuthenticityAnalyzer(cfg)
    fake_mail = MagicMock(attachments=[])

    res = analyzer.analyze(fake_mail)
    analyzer.shutdown()

    assert res.threat_score == 0.0
    assert res.risk_level == "low"
    assert res.suspicious_attachments == []


def test_analyze_with_single_safe_pdf():
    cfg = MagicMock(check_media_attachments=True, deepfake_detection_enabled=False)
    analyzer = MediaAuthenticityAnalyzer(cfg)
    fake_mail = MagicMock(
        attachments=[
            {
                "filename": "quarterly.pdf",
                "content_type": "application/pdf",
                "size": 48,
                "data": b"%PDF-1.4 header",
                "truncated": False,
            }
        ]
    )

    res = analyzer.analyze(fake_mail)
    analyzer.shutdown()

    assert res.threat_score == 0.0
    assert res.risk_level == "low"
    assert not res.file_type_warnings


def test_deepfake_bypassed_when_meta_score_is_critical():
    cfg = MagicMock(check_media_attachments=True, deepfake_detection_enabled=True)
    analyzer = MediaAuthenticityAnalyzer(cfg)
    fake_mail = MagicMock(
        attachments=[
            {
                "filename": "trojan.exe",
                "content_type": "application/octet-stream",
                "size": 128,
                "data": b"MZ\x00\x00",
                "truncated": False,
            },
            {
                "filename": "meeting.mp4",
                "content_type": "video/mp4",
                "size": 1024,
                "data": b"\x00\x00\x00\x18ftyp",
                "truncated": False,
            },
        ]
    )

    with patch.object(analyzer, "_check_deepfake_indicators") as mock_df:
        res = analyzer.analyze(fake_mail)
        analyzer.shutdown()

        assert res.threat_score >= 5.0
        mock_df.assert_not_called()
