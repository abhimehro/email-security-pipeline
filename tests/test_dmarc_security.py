
import pytest
from datetime import datetime
from src.modules.spam_analyzer import SpamAnalyzer, SpamAnalysisResult
from src.modules.email_ingestion import EmailData

# Mock config
class MockConfig:
    spam_threshold = 5.0
    spam_check_headers = True
    spam_check_urls = True

@pytest.fixture
def spam_analyzer():
    config = MockConfig()
    return SpamAnalyzer(config)

def test_dmarc_fail_detection(spam_analyzer):
    """
    Test that DMARC failure is detected in Authentication-Results header.

    SECURITY STORY: DMARC (Domain-based Message Authentication, Reporting, and Conformance)
    is crucial for preventing exact-domain spoofing. If SPF and DKIM pass but DMARC fails
    (e.g., due to misalignment), the email should be treated as suspicious.
    """
    # Email with DMARC failure but potentially passing SPF/DKIM (e.g. unaligned)
    headers = {
        "authentication-results": "mx.google.com; dkim=pass header.i=@example.com; spf=pass (google.com: domain of sender@example.com designates ...); dmarc=fail (p=REJECT dis=NONE) header.from=example.com",
        "from": "sender@example.com",
        "to": "recipient@company.com",
        "date": "Wed, 01 Jan 2025 00:00:00 -0000",
        "message-id": "<test@example.com>",
        "dkim-signature": "v=1; ..."
    }

    email_data = EmailData(
        message_id="1",
        subject="Test DMARC",
        sender="sender@example.com",
        recipient="recipient@company.com",
        date=datetime.now(),
        body_text="Test",
        body_html="",
        headers=headers,
        attachments=[],
        raw_email=None,
        account_email="recipient@company.com",
        folder="INBOX"
    )

    result = spam_analyzer.analyze(email_data)

    # Check if DMARC failure is detected
    found_dmarc_issue = False
    for issue in result.header_issues:
        if "DMARC" in issue and "fail" in issue.lower():
            found_dmarc_issue = True
            break

    assert found_dmarc_issue, "DMARC failure was not detected in headers"

    # DMARC fail is a strong signal, so score should be increased
    # We expect at least 2.5 points (similar to DKIM fail)
    assert result.score >= 2.5
