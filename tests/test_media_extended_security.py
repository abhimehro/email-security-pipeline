
import pytest
from unittest.mock import MagicMock
from datetime import datetime
import zipfile
import io
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

@pytest.fixture
def analyzer():
    config = MagicMock(spec=AnalysisConfig)
    config.check_media_attachments = True
    config.deepfake_detection_enabled = False # Disable for these tests
    return MediaAuthenticityAnalyzer(config)

def create_email_with_attachment(filename, data=b"dummy content"):
    return EmailData(
        message_id="test",
        subject="Test",
        sender="sender@example.com",
        recipient="recipient@example.com",
        date=datetime.now(),
        body_text="",
        body_html="",
        headers={},
        attachments=[{
            "filename": filename,
            "content_type": "application/octet-stream",
            "size": len(data),
            "data": data,
            "truncated": False
        }],
        raw_email=None,
        account_email="me@example.com",
        folder="INBOX"
    )

def test_missing_dangerous_extensions(analyzer):
    """Test extensions that are currently missing from the blocklist"""
    # List of extensions that SHOULD be blocked but might be missing
    extensions = ['.vbe', '.jse', '.wsh', '.scf', '.lnk', '.inf', '.reg', '.iso', '.img', '.vhd', '.vhdx']

    for ext in extensions:
        filename = f"malware{ext}"
        email = create_email_with_attachment(filename)
        result = analyzer.analyze(email)

        # We expect these to be flagged, but currently they might not be
        # If this test fails, it confirms the vulnerability exists (or rather, the test passes if I assert 0.0)
        # But I want to fail if they are NOT detected once I fix it.
        # For reproduction, I'll assert that they ARE detected, and expect failure.

        assert result.threat_score >= 5.0, f"Failed to detect dangerous extension: {ext}"

def test_nested_zip_evasion(analyzer):
    """Test that nested archives are flagged"""
    # Create inner zip
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, 'w') as zf:
        zf.writestr("payload.exe", b"malicious")
    inner_zip = inner_buffer.getvalue()

    # Create outer zip containing inner zip
    outer_buffer = io.BytesIO()
    with zipfile.ZipFile(outer_buffer, 'w') as zf:
        zf.writestr("nested.zip", inner_zip)
    outer_zip = outer_buffer.getvalue()

    email = create_email_with_attachment("archive.zip", outer_zip)
    result = analyzer.analyze(email)

    # Currently, this might pass (score 0) because .zip is not dangerous and we don't recurse
    # or flag nested zips.
    # We want it to be flagged.

    found_warning = False
    for warning in result.suspicious_attachments:
        if "nested archive" in warning or "dangerous file" in warning:
            found_warning = True
            break

    assert found_warning or result.threat_score >= 2.0, "Failed to detect nested archive"

def test_html_attachment(analyzer):
    """Test that HTML attachments are flagged as suspicious"""
    email = create_email_with_attachment("phishing.html")
    result = analyzer.analyze(email)
    assert result.threat_score >= 2.0, "Failed to detect HTML attachment"
