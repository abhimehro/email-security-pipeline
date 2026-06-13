"""
Unit tests for src/utils/threat_scoring.calculate_risk_level.

Verifies boundary conditions (exact threshold values, values just above and
below each boundary) and the full range of expected return labels.
"""

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

    # ------------------------------------------------------------------
    # Extreme float edge cases
    # ------------------------------------------------------------------

    def test_nan_score_is_low(self):
        """NaN >= threshold is False in Python, so it falls through to 'low'."""
        import math
        assert calculate_risk_level(float('nan'), 5.0, 10.0) == "low"

    def test_inf_score_is_high(self):
        assert calculate_risk_level(float('inf'), 5.0, 10.0) == "high"

    def test_negative_inf_score_is_low(self):
        assert calculate_risk_level(float('-inf'), 5.0, 10.0) == "low"

    def test_float_precision_boundary(self):
        """Test scores that are infinitesimally close to the boundary."""
        import math
        # Just below high_threshold (should be medium)
        just_below_high = math.nextafter(10.0, -math.inf)
        assert calculate_risk_level(just_below_high, 5.0, 10.0) == "medium"

        # Just above low_threshold (should be medium)
        just_above_low = math.nextafter(5.0, math.inf)
        assert calculate_risk_level(just_above_low, 5.0, 10.0) == "medium"

        # Just below low_threshold (should be low)
        just_below_low = math.nextafter(5.0, -math.inf)
        assert calculate_risk_level(just_below_low, 5.0, 10.0) == "low"

    def test_invalid_type_raises_typeerror(self):
        import pytest
        with pytest.raises(TypeError):
            calculate_risk_level(None, 5.0, 10.0) # type: ignore
