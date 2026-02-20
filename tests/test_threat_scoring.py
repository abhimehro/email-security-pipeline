"""
Unit tests for src/utils/threat_scoring.calculate_risk_level.

Verifies boundary conditions (exact threshold values, values just above and
below each boundary) and the full range of expected return labels.
"""

import pytest
from src.utils.threat_scoring import calculate_risk_level


class TestCalculateRiskLevel:
    """Tests for calculate_risk_level utility."""

    # ------------------------------------------------------------------
    # "low" region
    # ------------------------------------------------------------------

    def test_zero_score_is_low(self):
        assert calculate_risk_level(0.0, 5.0, 10.0) == "low"

    def test_score_below_low_threshold_is_low(self):
        assert calculate_risk_level(4.9, 5.0, 10.0) == "low"

    # ------------------------------------------------------------------
    # "medium" region
    # ------------------------------------------------------------------

    def test_score_equal_to_low_threshold_is_medium(self):
        """Exact low threshold should return 'medium' (inclusive lower bound)."""
        assert calculate_risk_level(5.0, 5.0, 10.0) == "medium"

    def test_score_between_thresholds_is_medium(self):
        assert calculate_risk_level(7.5, 5.0, 10.0) == "medium"

    def test_score_just_below_high_threshold_is_medium(self):
        assert calculate_risk_level(9.99, 5.0, 10.0) == "medium"

    # ------------------------------------------------------------------
    # "high" region
    # ------------------------------------------------------------------

    def test_score_equal_to_high_threshold_is_high(self):
        """Exact high threshold should return 'high' (inclusive lower bound)."""
        assert calculate_risk_level(10.0, 5.0, 10.0) == "high"

    def test_score_above_high_threshold_is_high(self):
        assert calculate_risk_level(99.0, 5.0, 10.0) == "high"

    # ------------------------------------------------------------------
    # Threshold configuration variants (mirrors real analyser call sites)
    # ------------------------------------------------------------------

    def test_spam_analyser_thresholds(self):
        """Mirrors SpamAnalyzer: low=threshold, high=threshold*2."""
        spam_threshold = 5.0
        assert calculate_risk_level(0.0, spam_threshold, spam_threshold * 2) == "low"
        assert calculate_risk_level(5.0, spam_threshold, spam_threshold * 2) == "medium"
        assert calculate_risk_level(10.0, spam_threshold, spam_threshold * 2) == "high"

    def test_nlp_analyser_thresholds(self):
        """Mirrors NLPThreatAnalyzer: threshold=nlp_threshold*10."""
        nlp_threshold = 0.5
        threshold = nlp_threshold * 10  # = 5.0
        assert calculate_risk_level(0.0, threshold, threshold * 2) == "low"
        assert calculate_risk_level(5.0, threshold, threshold * 2) == "medium"
        assert calculate_risk_level(10.0, threshold, threshold * 2) == "high"

    def test_media_analyser_thresholds(self):
        """Mirrors MediaAuthenticityAnalyzer class constants (2.0 / 5.0)."""
        assert calculate_risk_level(0.0, 2.0, 5.0) == "low"
        assert calculate_risk_level(1.9, 2.0, 5.0) == "low"
        assert calculate_risk_level(2.0, 2.0, 5.0) == "medium"
        assert calculate_risk_level(4.9, 2.0, 5.0) == "medium"
        assert calculate_risk_level(5.0, 2.0, 5.0) == "high"

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_equal_thresholds_low_wins(self):
        """When low == high, any score >= that value is 'high'."""
        assert calculate_risk_level(5.0, 5.0, 5.0) == "high"
        assert calculate_risk_level(4.9, 5.0, 5.0) == "low"

    def test_negative_score_is_low(self):
        assert calculate_risk_level(-1.0, 2.0, 5.0) == "low"
