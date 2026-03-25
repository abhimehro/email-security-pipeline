import unittest
from datetime import datetime
from unittest.mock import patch

from src.modules.email_ingestion import EmailData
from src.modules.nlp_analyzer import NLPThreatAnalyzer


# Mock config
class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = True
        self.nlp_threshold = 0.5
        self.nlp_model = "distilbert-base-uncased"
        self.enable_ml_model = True


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
            folder="Inbox",
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
            folder="Inbox",
        )

        result = self.analyzer.analyze(email)

        has_mismatch = any(
            "domain mismatch" in ind for ind in result.authority_impersonation
        )
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
            folder="Inbox",
        )

        result = self.analyzer.analyze(email)

        # Check if we have domain mismatch
        has_mismatch = any(
            "domain mismatch" in ind for ind in result.authority_impersonation
        )

        # As discussed, generic "CEO" match flags mismatch if "CEO" string not in sender domain.
        # "ceo" is not in "company.com" (substring check).
        # So mismatch is expected here with current logic.
        self.assertTrue(has_mismatch)

    def test_ml_model_disabled_skips_initialize(self):
        """When enable_ml_model=False, _initialize_model() must not be called."""
        config = MockConfig()
        config.enable_ml_model = False
        with patch.object(NLPThreatAnalyzer, "_initialize_model") as mock_init:
            NLPThreatAnalyzer(config)
            mock_init.assert_not_called()

    def test_ml_model_enabled_calls_initialize(self):
        """When enable_ml_model=True (default), _initialize_model() must be called."""
        config = MockConfig()
        config.enable_ml_model = True
        with patch.object(NLPThreatAnalyzer, "_initialize_model") as mock_init:
            NLPThreatAnalyzer(config)
            mock_init.assert_called_once()


if __name__ == "__main__":
    unittest.main()
