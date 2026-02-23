
import pytest
from datetime import datetime
from src.modules.spam_analyzer import SpamAnalyzer, SpamAnalysisResult
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

# Mock config
class MockConfig:
    spam_threshold = 5.0
    spam_check_headers = True
    spam_check_urls = True

@pytest.fixture
def spam_analyzer():
    config = MockConfig()
    return SpamAnalyzer(config)

@pytest.fixture
def clean_email():
    return EmailData(
        message_id="1",
        subject="Meeting tomorrow",
        sender="boss@company.com",
        recipient="me@company.com",
        date=datetime.now(),
        body_text="Hi, let's meet tomorrow at 10.",
        body_html="<html><body>Hi, let's meet tomorrow at 10.</body></html>",
        headers={
            "received-spf": "pass",
            "dkim-signature": "v=1; ...",
            "from": "boss@company.com",
            "to": "me@company.com",
            "date": "...",
            "message-id": "...",
            "received": "..."
        },
        attachments=[],
        raw_email=None,
        account_email="me@company.com",
        folder="INBOX"
    )

@pytest.fixture
def spam_email():
    return EmailData(
        message_id="2",
        subject="URGENT: WINNER PRIZE !!!",
        sender="spammer@example.com",
        recipient="victim@company.com",
        date=datetime.now(),
        body_text="CONGRATULATIONS! You are a WINNER. CLICK HERE to claim your FREE MONEY.",
        body_html="<html><body>CONGRATULATIONS! <a href='http://bit.ly/spam'>CLICK HERE</a> to claim. <img src='http://spam.com/pixel'> <img src='http://spam.com/pixel2'> <img src='http://spam.com/pixel3'></body></html>",
        headers={
            "received-spf": "fail",
            "from": "spammer@example.com",
            "to": "victim@company.com",
            "date": "...",
            "message-id": "..."
        },
        attachments=[],
        raw_email=None,
        account_email="victim@company.com",
        folder="INBOX"
    )

def test_clean_email_analysis(spam_analyzer, clean_email):
    result = spam_analyzer.analyze(clean_email)
    assert result.score < 2.0
    assert result.risk_level == "low"
    assert len(result.indicators) == 0

def test_spam_email_analysis(spam_analyzer, spam_email):
    result = spam_analyzer.analyze(spam_email)

    # Expected indicators:
    # - Subject caps (> 10 chars) -> 1.0
    # - Excessive punctuation in subject (!!!) -> 0.5
    # - Spam keywords in subject (urgent, winner, prize) -> 1.5 * N (but logic loops and breaks? No, it appends)
    # - Spam keywords in body -> 0.5 * count
    # - Excessive links? (only 1 link in spam_email) -> 0
    # - Image heavy? (body text length 70 > 50? No "CONGRATULATIONS!..." is > 50?)
    # - SPF fail -> 2.0

    # Just check it detects spam
    assert result.score > 5.0
    assert result.risk_level in ["medium", "high"]

    # Verify specific detections
    indicators_str = " ".join(result.indicators).lower()
    header_issues_str = " ".join(result.header_issues).lower()

    assert "spf check failed" in header_issues_str
    assert "subject in all caps" in indicators_str
    assert "spam keyword" in indicators_str

def test_spam_keywords_detection(spam_analyzer, clean_email):
    clean_email.body_text = "viagra pills available now"
    result = spam_analyzer.analyze(clean_email)

    # Should detect 2 matches (viagra, pills)
    # Score += 2 * 0.5 = 1.0
    found_keyword = False
    for indicator in result.indicators:
        if "Found 2 spam keyword matches" in indicator:
            found_keyword = True
            break
    assert found_keyword

def test_excessive_links(spam_analyzer, clean_email):
    links = " ".join([f"http://example{i}.com" for i in range(15)])
    clean_email.body_text = links
    result = spam_analyzer.analyze(clean_email)

    found_excessive = False
    for indicator in result.indicators:
        if "Excessive links" in indicator:
            found_excessive = True
            break
    assert found_excessive

def test_hidden_text(spam_analyzer, clean_email):
    clean_email.body_html = "<html><span style='font-size: 0px'>hidden</span></html>"
    result = spam_analyzer.analyze(clean_email)

    found_hidden = False
    for indicator in result.indicators:
        if "Hidden text detected" in indicator:
            found_hidden = True
            break
    assert found_hidden

def test_suspicious_urls(spam_analyzer, clean_email):
    clean_email.body_text = "Check this http://bit.ly/suspicious"
    result = spam_analyzer.analyze(clean_email)

    assert len(result.suspicious_urls) > 0
    assert "http://bit.ly/suspicious" in result.suspicious_urls

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
    # We expect at least 3.0 points (as implemented)
    assert result.score >= 3.0
