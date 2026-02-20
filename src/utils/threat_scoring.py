"""
Shared threat scoring utilities.

PATTERN RECOGNITION: Centralises risk-level calculation so that all
analysers use identical logic.  Previously each module contained its own
copy of the same if/elif ladder, making it easy to accidentally diverge
when the thresholds or labels change.

MAINTENANCE WISDOM: Any future changes to risk categorisation (e.g. adding
a "critical" tier) only need to happen here.
"""


def calculate_risk_level(
    score: float,
    low_threshold: float,
    high_threshold: float,
) -> str:
    """Return a standardised risk label for the given *score*.

    Args:
        score: The numeric threat score produced by an analyser.
        low_threshold: Minimum score that qualifies as ``"medium"`` risk.
        high_threshold: Minimum score that qualifies as ``"high"`` risk.

    Returns:
        One of ``"high"``, ``"medium"``, or ``"low"``.

    SECURITY STORY: By requiring callers to pass explicit thresholds, the
    function makes the risk boundaries visible at every call site.  This
    prevents the silent drift that occurs when hardcoded magic numbers are
    scattered across multiple modules.
    """
    if score >= high_threshold:
        return "high"
    if score >= low_threshold:
        return "medium"
    return "low"
