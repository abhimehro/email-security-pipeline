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
        self.nlp_model_revision = "main"
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

    def test_evaluate_rule_indicators_all_disabled(self):
        """Verify _evaluate_rule_indicators returns zero and empty lists when flags are off."""
        self.config.check_social_engineering = False
        self.config.check_urgency_markers = False
        self.config.check_authority_impersonation = False
        self.config.check_psychological_triggers = False

        matches = {
            "SE": {"Account verification request": 2},
            "UG": {"Time pressure": 1},
            "AU": {"Authority title": ["ceo"]},
            "PS": {"Reward temptation": 1},
        }

        score, se, ug, au, ps = self.analyzer._evaluate_rule_indicators(
            matches, exclamation_count=5, caps_count=4, sender="ceo@example.com"
        )
        self.assertEqual(score, 0.0)
        self.assertEqual(se, [])
        self.assertEqual(ug, [])
        self.assertEqual(au, [])
        self.assertEqual(ps, [])

    def test_evaluate_rule_indicators_all_enabled(self):
        """Verify _evaluate_rule_indicators accumulates scores and indicators when flags are on."""
        matches = {
            "SE": {"Account verification request": 1},
            "UG": {"Urgency keyword": 1},
            "AU": {"Authority title": ["ceo"]},
            "PS": {"Reward temptation": 1},
        }

        score, se, ug, au, ps = self.analyzer._evaluate_rule_indicators(
            matches, exclamation_count=4, caps_count=5, sender="ceo@random.com"
        )
        self.assertGreater(score, 0.0)
        self.assertEqual(len(se), 1)
        self.assertGreater(len(ug), 0)
        self.assertEqual(len(au), 1)
        self.assertEqual(len(ps), 1)

    def test_evaluate_ml_indicators_when_unloaded(self):
        """Verify _evaluate_ml_indicators returns (0.0, []) when model/tokenizer are absent."""
        self.analyzer.model = None
        self.analyzer.tokenizer = None
        email = EmailData(
            message_id="test",
            subject="Hello",
            sender="user@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="World",
            body_html="",
            headers={},
            attachments=[],
            raw_email=None,
            account_email="recipient@example.com",
            folder="Inbox",
        )
        score, indicators = self.analyzer._evaluate_ml_indicators(email)
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])

    def test_evaluate_ml_indicators_when_model_present(self):
        """Verify _evaluate_ml_indicators delegates to _run_transformer_analysis."""
        self.analyzer.model = object()
        self.analyzer.tokenizer = object()
        email = EmailData(
            message_id="test",
            subject="Hello",
            sender="user@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="World",
            body_html="",
            headers={},
            attachments=[],
            raw_email=None,
            account_email="recipient@example.com",
            folder="Inbox",
        )
        with patch.object(
            self.analyzer,
            "_run_transformer_analysis",
            return_value=(8.5, ["ML Threat Detected"]),
        ) as mock_run:
            score, indicators = self.analyzer._evaluate_ml_indicators(email)
            mock_run.assert_called_once_with(email)
            self.assertEqual(score, 8.5)
            self.assertEqual(indicators, ["ML Threat Detected"])


if __name__ == "__main__":
    unittest.main()
