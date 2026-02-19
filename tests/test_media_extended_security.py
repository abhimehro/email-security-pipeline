
import pytest
from unittest.mock import MagicMock
from datetime import datetime
import zipfile
import io
import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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
    extensions = ['.vbe', '.jse', '.wsh', '.scf', '.lnk', '.inf', '.reg', '.iso', '.img']

    for ext in extensions:
        filename = f"malware{ext}"
        email = create_email_with_attachment(filename)
        result = analyzer.analyze(email)

        assert result.threat_score >= 5.0, f"Failed to detect dangerous extension: {ext}"

def test_nested_zip_evasion(analyzer):
    """Test that nested archives are flagged and inspected recursively"""
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

    # 2.0 for nested archive + 5.0 for .exe inside it (via recursion) = 7.0

    found_nested_warning = any("nested archive" in w for w in result.suspicious_attachments)
    found_exe_warning = any("dangerous file" in w for w in result.suspicious_attachments)

    assert found_nested_warning, "Failed to detect nested archive wrapper"
    assert found_exe_warning, "Failed to detect dangerous file inside nested archive (recursion failed)"
    assert result.threat_score >= 7.0, f"Threat score too low: {result.threat_score}"

def test_html_attachment(analyzer):
    """Test that HTML attachments are flagged as suspicious"""
    email = create_email_with_attachment("phishing.html")
    result = analyzer.analyze(email)
    assert result.threat_score >= 2.0, "Failed to detect HTML attachment"
