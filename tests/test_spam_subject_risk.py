"""Unit tests for SpamAnalyzer._analyze_subject and _calculate_risk_level.

PATTERN RECOGNITION: These tests call private methods directly to verify
threshold boundary conditions that are invisible through the public analyze()
API.  Boundary tests are the primary defence against off-by-one regressions
in the scoring logic.

SECURITY STORY: _analyze_subject scores the subject line on every email
processed.  The all-caps and exclamation thresholds are off-by-one sensitive.
_calculate_risk_level determines whether an alert fires; the multipliers used
to derive medium/high thresholds from spam_threshold are tested here to make
accidental drift immediately visible.
"""

import pytest

from src.modules.spam_analyzer import SpamAnalyzer


class MockConfig:
    """Minimal config with a controlled spam_threshold for boundary testing."""

    spam_threshold = 0.5
    spam_check_headers = True
    spam_check_urls = True


@pytest.fixture
def analyzer():
    return SpamAnalyzer(MockConfig())


class TestAnalyzeSubject:
    """Tests for SpamAnalyzer._analyze_subject."""

    def test_clean_short_subject_no_score(self, analyzer):
        """A plain short subject should produce zero score and no indicators."""
        score, indicators = analyzer._analyze_subject("Hello")
        assert score == 0.0
        assert indicators == []

    def test_all_caps_exactly_10_chars_no_trigger(self, analyzer):
        """All-caps at exactly 10 chars must NOT trigger (boundary: len > 10)."""
        score, indicators = analyzer._analyze_subject("HELLO WORL")
        # len("HELLO WORL") == 10, which is not > 10
        assert score == 0.0
        assert "Subject in all caps" not in indicators

    def test_all_caps_11_chars_triggers(self, analyzer):
        """All-caps subject longer than 10 chars should add 1.0 and flag."""
        score, indicators = analyzer._analyze_subject("HELLO WORLD!")
        # len("HELLO WORLD!") == 12, isupper() is True (! is not a cased char)
        assert score >= 1.0
        assert "Subject in all caps" in indicators

    def test_exactly_2_exclamations_no_trigger(self, analyzer):
        """Exactly 2 '!' must NOT trigger (boundary: count > 2)."""
        score, indicators = analyzer._analyze_subject("Hi!!")
        assert score == 0.0
        assert "Excessive exclamation marks" not in indicators

    def test_3_exclamations_triggers(self, analyzer):
        """Three '!' should add 0.5 and flag excessive punctuation."""
        score, indicators = analyzer._analyze_subject("Hi!!!")
        assert score == pytest.approx(0.5)
        assert "Excessive exclamation marks" in indicators

    def test_spam_keyword_in_subject(self, analyzer):
        """A known spam keyword phrase should add 1.5 per unique match and flag."""
        score, indicators = analyzer._analyze_subject("free money offer")
        assert score >= 1.5
        assert any("Spam keyword in subject" in ind for ind in indicators)

    def test_money_pattern_in_subject(self, analyzer):
        """A dollar amount in the subject should add 0.5 and flag."""
        score, indicators = analyzer._analyze_subject("win $500 today")
        assert score >= 0.5
        assert "Money mentioned in subject" in indicators


class TestCalculateRiskLevel:
    """Tests for SpamAnalyzer._calculate_risk_level.

    With MockConfig.spam_threshold = 0.5:
      medium cutoff  = spam_threshold       = 0.5
      high cutoff    = spam_threshold * 2   = 1.0
    """

    def test_low_risk_below_medium_threshold(self, analyzer):
        """Score below medium threshold (spam_threshold) should return 'low'."""
        assert analyzer._calculate_risk_level(0.0) == "low"

    def test_medium_at_exact_threshold(self, analyzer):
        """Score exactly at spam_threshold should return 'medium'."""
        assert analyzer._calculate_risk_level(0.5) == "medium"

    def test_medium_below_high_threshold(self, analyzer):
        """Score above medium but below high threshold should return 'medium'."""
        assert analyzer._calculate_risk_level(0.9) == "medium"

    def test_high_at_exact_high_threshold(self, analyzer):
        """Score at or above spam_threshold * 2 should return 'high'."""
        assert analyzer._calculate_risk_level(1.0) == "high"
