
import pytest
from src.modules.spam_analyzer import SpamAnalyzer, SpamAnalysisResult
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig
from datetime import datetime

# Mock config
class MockConfig:
    spam_threshold = 5.0
    spam_check_headers = True
    spam_check_urls = True

@pytest.fixture
def spam_analyzer():
    config = MockConfig()
    return SpamAnalyzer(config)

def test_multiple_received_headers(spam_analyzer):
    # Create headers with multiple Received entries (simulating list)
    headers = {
        "received": [f"hop{i}" for i in range(15)], # 15 hops
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "date": "...",
        "message-id": "...",
        "dkim-signature": "pass"
    }

    email_data = EmailData(
        message_id="1", subject="Test", sender="sender", recipient="recip",
        date=datetime.now(), body_text="", body_html="",
        headers=headers, attachments=[], raw_email=None,
        account_email="", folder=""
    )

    result = spam_analyzer.analyze(email_data)

    assert "Excessive hops in delivery path" in result.header_issues
    assert result.score >= 1.0

def test_multiple_from_headers(spam_analyzer):
    # Multiple From headers
    headers = {
        "from": ["sender1@example.com", "sender2@example.com"],
        "to": "recipient@example.com",
        "date": "...",
        "message-id": "...",
        "dkim-signature": "pass"
    }

    email_data = EmailData(
        message_id="1", subject="Test", sender="sender", recipient="recip",
        date=datetime.now(), body_text="", body_html="",
        headers=headers, attachments=[], raw_email=None,
        account_email="", folder=""
    )

    result = spam_analyzer.analyze(email_data)

    assert "Multiple From headers detected" in result.header_issues
    assert result.score >= 2.0

def test_spf_fail_mixed(spam_analyzer):
    # One pass, one fail in SPF
    headers = {
        "received-spf": ["pass", "fail"],
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "date": "...",
        "message-id": "...",
        "dkim-signature": "pass"
    }

    email_data = EmailData(
        message_id="1", subject="Test", sender="sender", recipient="recip",
        date=datetime.now(), body_text="", body_html="",
        headers=headers, attachments=[], raw_email=None,
        account_email="", folder=""
    )

    result = spam_analyzer.analyze(email_data)

    assert "SPF check failed" in result.header_issues
    assert result.score >= 2.0
