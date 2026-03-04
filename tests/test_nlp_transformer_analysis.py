"""
Unit tests for NLPThreatAnalyzer._run_transformer_analysis

Tests cover:
  - Score mapping: threat_probability → (prob - 0.5) * 20 when prob > 0.5
  - Error handling: "error" key in transformer_results → (0.0, [])
  - Text preparation: subject + body budget, long-subject truncation
"""

import unittest
from datetime import datetime
from unittest.mock import MagicMock

from src.modules.nlp_analyzer import NLPThreatAnalyzer
from src.modules.email_data import EmailData


class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = False
        self.nlp_threshold = 0.5
        self.nlp_model = "distilbert-base-uncased"


def _make_email(subject: str = "subject", body_text: str = "body") -> EmailData:
    return EmailData(
        message_id="test-1",
        subject=subject,
        sender="test@example.com",
        recipient="user@example.com",
        date=datetime(2026, 1, 1),
        body_text=body_text,
        body_html="",
        headers={},
        attachments=[],
        raw_email=None,
        account_email="user@example.com",
        folder="Inbox",
    )


class TestRunTransformerAnalysisScoring(unittest.TestCase):
    """Score-mapping: (prob - 0.5) * 20 for prob > 0.5, else 0.0"""

    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)
        # Disable real model to isolate _run_transformer_analysis
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()

    def _call(self, threat_probability):
        """Helper: mock analyze_with_transformer and invoke the method."""
        self.analyzer.analyze_with_transformer = MagicMock(
            return_value={"threat_probability": threat_probability}
        )
        return self.analyzer._run_transformer_analysis(_make_email())

    def test_prob_exactly_0_5_yields_zero_score(self):
        """Boundary: prob == 0.5 must NOT trigger scoring (strictly > 0.5 required)."""
        score, indicators = self._call(0.5)
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])

    def test_prob_just_above_threshold_yields_small_score(self):
        """prob = 0.501 → score ≈ 0.02; indicator present."""
        score, indicators = self._call(0.501)
        self.assertAlmostEqual(score, (0.501 - 0.5) * 20, places=5)
        self.assertEqual(len(indicators), 1)
        self.assertIn("0.50", indicators[0])

    def test_prob_0_75_yields_5_points(self):
        score, indicators = self._call(0.75)
        self.assertAlmostEqual(score, 5.0)
        self.assertEqual(len(indicators), 1)

    def test_prob_1_0_yields_10_points(self):
        """Maximum: prob = 1.0 → exactly 10.0 points."""
        score, indicators = self._call(1.0)
        self.assertAlmostEqual(score, 10.0)
        self.assertEqual(len(indicators), 1)

    def test_prob_below_threshold_yields_zero(self):
        """prob = 0.3 < 0.5 → score 0.0, no indicators."""
        score, indicators = self._call(0.3)
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])


class TestRunTransformerAnalysisErrors(unittest.TestCase):
    """Error handling: 'error' key → silent (0.0, []) return."""

    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()

    def test_error_key_returns_zero_no_exception(self):
        """analyze_with_transformer returns {'error': '...'} → (0.0, [])."""
        self.analyzer.analyze_with_transformer = MagicMock(
            return_value={"error": "Model not loaded"}
        )
        score, indicators = self.analyzer._run_transformer_analysis(_make_email())
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])

    def test_missing_threat_probability_key_returns_zero(self):
        """analyze_with_transformer returns {} (no threat_probability) → (0.0, [])."""
        self.analyzer.analyze_with_transformer = MagicMock(return_value={})
        score, indicators = self.analyzer._run_transformer_analysis(_make_email())
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])


class TestRunTransformerAnalysisTextPrep(unittest.TestCase):
    """Text preparation: subject + body budget split at 4096 chars."""

    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()
        # Return a benign result so scoring doesn't interfere
        self.analyzer.analyze_with_transformer = MagicMock(
            return_value={"threat_probability": 0.0}
        )

    def _captured_text(self):
        """Return the text that was passed to analyze_with_transformer."""
        return self.analyzer.analyze_with_transformer.call_args[0][0]

    def test_short_subject_body_concatenation(self):
        """Short subject (10 chars) + body → 'subject body[:4085]'."""
        subject = "A" * 10
        body = "B" * 200
        email = _make_email(subject=subject, body_text=body)
        self.analyzer._run_transformer_analysis(email)
        text = self._captured_text()
        # Expected: subject + " " + body[:4096 - 10 - 1]
        expected = subject + " " + body[: 4096 - 10 - 1]
        self.assertEqual(text, expected)

    def test_subject_4095_chars_body_zero(self):
        """Subject of 4095 chars leaves body budget = 4096 - 4095 - 1 = 0 chars."""
        subject = "S" * 4095
        body = "B" * 100
        email = _make_email(subject=subject, body_text=body)
        self.analyzer._run_transformer_analysis(email)
        text = self._captured_text()
        # subject_len + 1 == 4096 == max_len → condition (>= max_len) is True,
        # so ml_text is subject[:4096] and the body is not included.
        self.assertEqual(text, subject[:4096])

    def test_subject_longer_than_max_truncated_only(self):
        """Subject >= 4096 chars → only subject[:4096] sent, no body."""
        subject = "X" * 5000
        body = "Y" * 100
        email = _make_email(subject=subject, body_text=body)
        self.analyzer._run_transformer_analysis(email)
        text = self._captured_text()
        self.assertEqual(text, subject[:4096])
        self.assertNotIn("Y", text)

    def test_subject_4094_chars_body_gets_one_char(self):
        """Subject 4094 chars → body budget = 4096 - 4094 - 1 = 1 char."""
        subject = "S" * 4094
        body = "BZ" * 10
        email = _make_email(subject=subject, body_text=body)
        self.analyzer._run_transformer_analysis(email)
        text = self._captured_text()
        # subject_len + 1 = 4095 < 4096 → else branch
        expected = subject + " " + body[:1]
        self.assertEqual(text, expected)


if __name__ == "__main__":
    unittest.main()
