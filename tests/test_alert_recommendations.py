"""
Unit tests for AlertSystem._generate_recommendations branch logic.

SECURITY STORY: _generate_recommendations translates threat analysis results
into actionable user guidance. If any conditional branch were silently broken
(e.g., by an attribute rename during refactor), users receiving phishing emails
or dangerous attachments would no longer see the corresponding warning — a
silent security regression. These tests make each branch's exact trigger
condition explicit and regression-proof.
"""

import unittest

from src.modules.alert_system import AlertSystem
from src.modules.spam_analyzer import SpamAnalysisResult
from src.modules.nlp_analyzer import NLPAnalysisResult
from src.modules.media_analyzer import MediaAnalysisResult


def _make_spam(risk_level="low", suspicious_urls=None):
    """Return a SpamAnalysisResult with safe defaults."""
    return SpamAnalysisResult(
        score=0.0,
        indicators=[],
        suspicious_urls=suspicious_urls or [],
        header_issues=[],
        risk_level=risk_level,
    )


def _make_nlp(
    social_engineering_indicators=None,
    authority_impersonation=None,
    urgency_markers=None,
):
    """Return an NLPAnalysisResult with safe defaults."""
    return NLPAnalysisResult(
        threat_score=0.0,
        social_engineering_indicators=social_engineering_indicators or [],
        urgency_markers=urgency_markers or [],
        authority_impersonation=authority_impersonation or [],
        psychological_triggers=[],
        risk_level="low",
    )


def _make_media(file_type_warnings=None):
    """Return a MediaAnalysisResult with safe defaults."""
    return MediaAnalysisResult(
        threat_score=0.0,
        suspicious_attachments=[],
        file_type_warnings=file_type_warnings or [],
        size_anomalies=[],
        potential_deepfakes=[],
        risk_level="low",
    )


class TestGenerateRecommendations(unittest.TestCase):
    """Direct unit tests for AlertSystem._generate_recommendations."""

    def test_recommendation_keyword_patterns_match_expected_terms(self):
        """Regression test: class-level recommendation regexes remain import-safe and usable."""
        self.assertIsNotNone(
            AlertSystem.RED_KEYWORDS_PATTERN.search("HIGH RISK sender"),
        )
        self.assertIsNotNone(
            AlertSystem.RED_KEYWORDS_PATTERN.search("DANGEROUS attachment"),
        )
        self.assertIsNotNone(
            AlertSystem.YELLOW_KEYWORDS_PATTERN.search("VERIFY sender identity"),
        )
        self.assertIsNotNone(
            AlertSystem.YELLOW_KEYWORDS_PATTERN.search("URGENCY tactics detected"),
        )

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def test_fallback_all_conditions_false(self):
        """No conditions triggered → exactly the generic fallback recommendation."""
        result = AlertSystem._generate_recommendations(
            _make_spam(), _make_nlp(), _make_media()
        )
        self.assertEqual(result, [AlertSystem.DEFAULT_CLEAN_RECOMMENDATION])

    # ------------------------------------------------------------------
    # Individual branch tests
    # ------------------------------------------------------------------

    def test_high_spam_risk_level(self):
        """spam_result.risk_level == 'high' → HIGH RISK recommendation included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(risk_level="high"), _make_nlp(), _make_media()
        )
        self.assertTrue(
            any("HIGH RISK" in r for r in result),
            f"Expected 'HIGH RISK' in recommendations, got: {result}",
        )

    def test_social_engineering_indicators(self):
        """Truthy social_engineering_indicators → phishing recommendation included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(),
            _make_nlp(social_engineering_indicators=["Account verification request"]),
            _make_media(),
        )
        self.assertTrue(
            any("Potential phishing" in r for r in result),
            f"Expected 'Potential phishing' in recommendations, got: {result}",
        )

    def test_file_type_warnings(self):
        """Truthy file_type_warnings → dangerous-attachment recommendation included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(),
            _make_nlp(),
            _make_media(file_type_warnings=["exe file detected"]),
        )
        self.assertTrue(
            any("Dangerous attachment" in r for r in result),
            f"Expected 'Dangerous attachment' in recommendations, got: {result}",
        )

    def test_suspicious_urls(self):
        """Truthy suspicious_urls → suspicious-URLs recommendation included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(suspicious_urls=["bit.ly/redacted"]),
            _make_nlp(),
            _make_media(),
        )
        self.assertTrue(
            any("Suspicious URLs" in r for r in result),
            f"Expected 'Suspicious URLs' in recommendations, got: {result}",
        )

    def test_authority_impersonation(self):
        """Truthy authority_impersonation → authority-impersonation recommendation included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(),
            _make_nlp(authority_impersonation=["CEO impersonation"]),
            _make_media(),
        )
        self.assertTrue(
            any("Authority impersonation" in r for r in result),
            f"Expected 'Authority impersonation' in recommendations, got: {result}",
        )

    def test_urgency_markers(self):
        """Truthy urgency_markers → urgency-tactics recommendation included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(),
            _make_nlp(urgency_markers=["Urgent!"]),
            _make_media(),
        )
        self.assertTrue(
            any("Urgency tactics" in r for r in result),
            f"Expected 'Urgency tactics' in recommendations, got: {result}",
        )

    # ------------------------------------------------------------------
    # Multi-branch test
    # ------------------------------------------------------------------

    def test_multiple_conditions_all_recommendations_returned(self):
        """Multiple conditions simultaneously → all matching recommendations returned, no fallback."""
        result = AlertSystem._generate_recommendations(
            _make_spam(risk_level="high", suspicious_urls=["bit.ly/suspicious"]),
            _make_nlp(
                social_engineering_indicators=["Account verification request"],
                authority_impersonation=["CEO impersonation"],
                urgency_markers=["Urgent!"],
            ),
            _make_media(file_type_warnings=["exe file detected"]),
        )

        self.assertTrue(any("HIGH RISK" in r for r in result))
        self.assertTrue(any("Potential phishing" in r for r in result))
        self.assertTrue(any("Dangerous attachment" in r for r in result))
        self.assertTrue(any("Suspicious URLs" in r for r in result))
        self.assertTrue(any("Authority impersonation" in r for r in result))
        self.assertTrue(any("Urgency tactics" in r for r in result))
        # Fallback must NOT appear when real recommendations are present
        self.assertFalse(
            any("Review email carefully" in r for r in result),
            "Fallback should not appear when other recommendations are present",
        )

    # ------------------------------------------------------------------
    # No-high-spam test
    # ------------------------------------------------------------------

    def test_medium_spam_risk_level_no_high_risk_recommendation(self):
        """spam_result.risk_level == 'medium' → HIGH RISK recommendation NOT included."""
        result = AlertSystem._generate_recommendations(
            _make_spam(risk_level="medium"), _make_nlp(), _make_media()
        )
        self.assertFalse(
            any("HIGH RISK" in r for r in result),
            f"'HIGH RISK' should not appear for medium risk, got: {result}",
        )


if __name__ == "__main__":
    unittest.main()
