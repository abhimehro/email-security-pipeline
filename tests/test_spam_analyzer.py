from datetime import datetime

import pytest

from src.modules.email_ingestion import EmailData
from src.modules.spam_analyzer import SpamAnalyzer


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
            "received": "...",
        },
        attachments=[],
        raw_email=None,
        account_email="me@company.com",
        folder="INBOX",
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
            "message-id": "...",
        },
        attachments=[],
        raw_email=None,
        account_email="victim@company.com",
        folder="INBOX",
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


def test_sender_freemail_detection(spam_analyzer, clean_email):
    """Test that corporate titles from freemail domains are flagged correctly."""
    clean_email.sender = "CEO <ceo@gmail.com>"
    result = spam_analyzer.analyze(clean_email)

    assert "Corporate title with freemail provider" in result.indicators
    # Score should increase by 1.5 for this specific rule
    assert result.score >= 1.5


def test_sender_freemail_detection_negative(spam_analyzer, clean_email):
    """Test that corporate titles from non-freemail domains are NOT flagged."""
    clean_email.sender = "CEO <ceo@notgmail.com>"
    result = spam_analyzer.analyze(clean_email)

    assert "Corporate title with freemail provider" not in result.indicators


def test_sender_freemail_detection_false_positive(spam_analyzer, clean_email):
    """Test that domains merely containing freemail provider strings as a substring are NOT flagged."""
    clean_email.sender = "CEO <ceo@gmail.com.scam.net>"
    result = spam_analyzer.analyze(clean_email)

    assert "Corporate title with freemail provider" not in result.indicators


def test_sender_display_name_extraction(spam_analyzer, clean_email):
    # Valid Name <email> with mismatched domains in display name
    clean_email.sender = '"CEO @ company.com" <ceo@freemail.com>'
    score, indicators = spam_analyzer._check_sender(
        clean_email.sender, clean_email.headers
    )
    assert score >= 1.0
    assert "Suspicious display name format" in indicators

    # NameOnly - no < email > part, should not trigger index extraction mismatch
    clean_email.sender = "Just a normal name"
    score, indicators = spam_analyzer._check_sender(
        clean_email.sender, clean_email.headers
    )
    assert score == 0.0
    assert not any("Suspicious display name format" in ind for ind in indicators)

    # <email> only - idx is 0, should not extract a display name
    clean_email.sender = "<ceo@company.com>"
    score, indicators = spam_analyzer._check_sender(
        clean_email.sender, clean_email.headers
    )
    assert score == 0.0
    assert not any("Suspicious display name format" in ind for ind in indicators)

    # Match case sensitivity handling
    clean_email.sender = '"Admin.COMPANY" <admin@freemail.com>'
    score, indicators = spam_analyzer._check_sender(
        clean_email.sender, clean_email.headers
    )
    assert score >= 1.0
    assert "Suspicious display name format" in indicators
