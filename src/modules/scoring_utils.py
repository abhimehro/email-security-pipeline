"""
Reusable threat scoring accumulator utility.

PATTERN RECOGNITION: This is the Accumulator pattern - a single object
maintains running state (score + indicators) and provides atomic add()
operations, eliminating repetitive `score +=` / `indicators.extend()`
boilerplate that was previously scattered across every analyzer module.
"""

from typing import Callable, List, Optional, Tuple


class ThreatScorer:
    """Accumulates a threat score and a flat list of indicator strings.

    MAINTENANCE WISDOM: Using this class instead of bare local variables
    means any future change to how scores are capped, rounded, or logged
    only needs to be made here, not in every analyzer.

    SECURITY STORY: Centralising score accumulation prevents a class of
    subtle bugs where one code path forgets to add a score component,
    leading to an under-reported threat level.

    Usage::

        scorer = ThreatScorer()
        scorer.add(score, indicators)           # flat list
        scorer.add(score)                        # score-only
        threat_score, risk_level = scorer.finalize(self._calculate_risk_level)
    """

    def __init__(self) -> None:
        self.score: float = 0.0
        self.indicators: List[str] = []

    def add(self, score: float, indicators: Optional[List[str]] = None) -> None:
        """Accumulate *score* and optionally extend *indicators*.

        Args:
            score:      Threat score increment (positive to raise, negative
                        to lower the running total if a check is retracted).
            indicators: Optional list of human-readable indicator strings.
                        A bare string is accepted and wrapped in a list.
        """
        self.score += score
        if indicators is not None:
            if isinstance(indicators, str):
                # TEACHING MOMENT: accepting a bare string prevents a
                # hard-to-spot bug where callers pass one string instead
                # of a list and silently get each *character* extended.
                indicators = [indicators]
            self.indicators.extend(indicators)

    def finalize(self, risk_calculator: Callable[[float], str]) -> Tuple[float, str]:
        """Return *(total_score, risk_level)* using the provided calculator.

        Args:
            risk_calculator: A callable that maps a float score to a
                             risk-level string (e.g. "low"/"medium"/"high").

        Returns:
            Tuple of (accumulated score, risk level string).
        """
        return self.score, risk_calculator(self.score)
