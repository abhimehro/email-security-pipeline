"""
Unit tests for ThreatScorer utility (src/modules/scoring_utils.py).

Covers: basic accumulation, score-only adds, string normalisation,
empty indicator lists, finalize delegation, and zero-score behaviour.
"""

import pytest
from src.modules.scoring_utils import ThreatScorer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _risk_stub(score: float) -> str:
    """Minimal risk calculator used to exercise finalize() without coupling
    to any real analyzer's thresholds."""
    if score >= 5.0:
        return "high"
    if score >= 2.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestThreatScorerInit:
    def test_initial_score_is_zero(self):
        assert ThreatScorer().score == 0.0

    def test_initial_indicators_empty(self):
        assert ThreatScorer().indicators == []


# ---------------------------------------------------------------------------
# add() – score accumulation
# ---------------------------------------------------------------------------

class TestThreatScorerAdd:
    def test_single_score_add(self):
        scorer = ThreatScorer()
        scorer.add(1.5)
        assert scorer.score == pytest.approx(1.5)

    def test_multiple_score_adds(self):
        scorer = ThreatScorer()
        scorer.add(1.0)
        scorer.add(2.5)
        scorer.add(0.5)
        assert scorer.score == pytest.approx(4.0)

    def test_zero_score_add(self):
        scorer = ThreatScorer()
        scorer.add(0.0)
        assert scorer.score == pytest.approx(0.0)

    def test_float_precision(self):
        scorer = ThreatScorer()
        for _ in range(10):
            scorer.add(0.1)
        assert scorer.score == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# add() – indicator accumulation
# ---------------------------------------------------------------------------

class TestThreatScorerIndicators:
    def test_indicators_extend_on_each_add(self):
        scorer = ThreatScorer()
        scorer.add(1.0, ["A"])
        scorer.add(2.0, ["B", "C"])
        assert scorer.indicators == ["A", "B", "C"]

    def test_none_indicators_ignored(self):
        scorer = ThreatScorer()
        scorer.add(1.0, None)
        assert scorer.indicators == []

    def test_no_indicators_argument(self):
        scorer = ThreatScorer()
        scorer.add(1.0)
        assert scorer.indicators == []

    def test_empty_list_indicators(self):
        scorer = ThreatScorer()
        scorer.add(1.0, [])
        assert scorer.indicators == []

    def test_bare_string_normalised_to_list(self):
        """A bare string must not be iterated character-by-character."""
        scorer = ThreatScorer()
        scorer.add(1.0, "single indicator")  # type: ignore[arg-type]
        assert scorer.indicators == ["single indicator"]

    def test_order_preserved(self):
        scorer = ThreatScorer()
        scorer.add(1.0, ["first"])
        scorer.add(1.0, ["second", "third"])
        scorer.add(1.0, ["fourth"])
        assert scorer.indicators == ["first", "second", "third", "fourth"]


# ---------------------------------------------------------------------------
# finalize()
# ---------------------------------------------------------------------------

class TestThreatScorerFinalize:
    def test_finalize_returns_score_and_risk(self):
        scorer = ThreatScorer()
        scorer.add(3.0)
        score, risk = scorer.finalize(_risk_stub)
        assert score == pytest.approx(3.0)
        assert risk == "medium"

    def test_finalize_high_risk(self):
        scorer = ThreatScorer()
        scorer.add(6.0)
        _, risk = scorer.finalize(_risk_stub)
        assert risk == "high"

    def test_finalize_low_risk(self):
        scorer = ThreatScorer()
        _, risk = scorer.finalize(_risk_stub)
        assert risk == "low"

    def test_finalize_does_not_reset_state(self):
        """finalize() is read-only; subsequent adds should still work."""
        scorer = ThreatScorer()
        scorer.add(2.0)
        scorer.finalize(_risk_stub)
        scorer.add(1.0)
        score, _ = scorer.finalize(_risk_stub)
        assert score == pytest.approx(3.0)

    def test_finalize_uses_provided_calculator(self):
        """finalize() must delegate to the supplied callable, not a hardcoded one."""
        def always_critical(_s: float) -> str:
            return "critical"

        scorer = ThreatScorer()
        _, risk = scorer.finalize(always_critical)
        assert risk == "critical"


# ---------------------------------------------------------------------------
# Integration: mirrors analyzer usage patterns
# ---------------------------------------------------------------------------

class TestThreatScorerIntegration:
    def test_nlp_pattern_score_only_adds(self):
        """nlp_analyzer accumulates score via add(score) while keeping
        separate indicator lists – verify the scorer still totals correctly."""
        scorer = ThreatScorer()
        social_engineering = []
        urgency_markers = []

        se_score, se_inds = 2.0, ["social eng indicator"]
        scorer.add(se_score)
        social_engineering.extend(se_inds)

        ug_score, ug_inds = 1.5, ["urgency marker"]
        scorer.add(ug_score)
        urgency_markers.extend(ug_inds)

        assert scorer.score == pytest.approx(3.5)
        assert scorer.indicators == []          # scorer itself has none
        assert social_engineering == ["social eng indicator"]
        assert urgency_markers == ["urgency marker"]

    def test_spam_pattern_combined_adds(self):
        """spam_analyzer calls scorer.add(*result_tuple) where result_tuple
        is (score, indicators) – mirrors the star-unpack usage."""
        scorer = ThreatScorer()

        def mock_analyze_subject():
            return 1.5, ["Subject in all caps"]

        def mock_analyze_body():
            return 2.0, ["Found 3 spam keyword matches"]

        scorer.add(*mock_analyze_subject())
        scorer.add(*mock_analyze_body())

        assert scorer.score == pytest.approx(3.5)
        assert "Subject in all caps" in scorer.indicators
        assert "Found 3 spam keyword matches" in scorer.indicators

    def test_media_pattern_score_threshold_check(self):
        """media_analyzer uses scorer.score < 5.0 as a guard before deepfake
        checks – ensure the live score is accessible mid-loop."""
        scorer = ThreatScorer()
        scorer.add(3.0)
        assert scorer.score < 5.0  # deepfake check would proceed

        scorer.add(3.0)
        assert scorer.score >= 5.0  # deepfake check would be skipped
