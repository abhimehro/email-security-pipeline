
import unittest
from datetime import datetime
from src.modules.nlp_analyzer import NLPThreatAnalyzer
from src.modules.email_ingestion import EmailData

# Mock config
class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = True
        self.nlp_threshold = 0.5
        self.nlp_model = 'distilbert-base-uncased'

class TestNLPAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)
        # Disable ML model for speed/determinism in this test unless needed
        self.analyzer.model = None
        self.analyzer.tokenizer = None

    def test_social_engineering_detection(self):
        email = EmailData(
            message_id="1",
            subject="Urgent: Verify your account",
            sender="support@bank.com",
            recipient="user@example.com",
            date=datetime.now(),
            body_text="Please verify your credentials immediately to avoid account suspension.",
            body_html="",
            headers={},
            attachments=[],
            raw_email=None,
            account_email="user@example.com",
            folder="Inbox"
        )

        result = self.analyzer.analyze(email)

        self.assertGreater(len(result.social_engineering_indicators), 0)
        self.assertGreater(len(result.urgency_markers), 0)

    def test_authority_impersonation(self):
        # Mismatch case
        email = EmailData(
            message_id="2",
            subject="Message from CEO",
            sender="ceo@random-domain.com",
            recipient="user@example.com",
            date=datetime.now(),
            body_text="I am the CEO. Please send gift cards.",
            body_html="",
            headers={},
            attachments=[],
            raw_email=None,
            account_email="user@example.com",
            folder="Inbox"
        )

        result = self.analyzer.analyze(email)

        has_mismatch = any("domain mismatch" in ind for ind in result.authority_impersonation)
        self.assertTrue(has_mismatch)

    def test_authority_impersonation_edge_case(self):
        # Edge case: generic title that still triggers a mismatch
        email = EmailData(
            message_id="3",
            subject="Message from CEO",
            sender="ceo@company.com",
            recipient="user@company.com",
            date=datetime.now(),
            body_text="I am the CEO. Good job.",
            body_html="",
            headers={},
            attachments=[],
            raw_email=None,
            account_email="user@company.com",
            folder="Inbox"
        )

        result = self.analyzer.analyze(email)

        # Check if we have domain mismatch
        has_mismatch = any("domain mismatch" in ind for ind in result.authority_impersonation)

        # As discussed, generic "CEO" match flags mismatch if "CEO" string not in sender domain.
        # "ceo" is not in "company.com" (substring check).
        # So mismatch is expected here with current logic.
        self.assertTrue(has_mismatch)

if __name__ == '__main__':
    unittest.main()
