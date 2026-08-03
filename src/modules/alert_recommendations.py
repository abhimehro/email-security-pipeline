"""
Alert recommendations generation.

Turns per-layer analysis results into actionable user guidance.
"""

import re
from typing import List

from .media_analyzer import MediaAnalysisResult
from .nlp_analyzer import NLPAnalysisResult
from .spam_analyzer import SpamAnalysisResult

# Common prefixes for recommendations to strip during display to prevent duplication
RECOMMENDATION_PREFIXES = ["⚠️ ", "🎣 ", "🔗 ", "⏰ ", "📎 ", "👤 "]

# Pre-allocated tuple for fast C-level execution of startswith()
RECOMMENDATION_PREFIXES_TUPLE = tuple(RECOMMENDATION_PREFIXES)

# Compiled regex patterns for fast substring keyword checks in recommendations
# Use re.compile directly since we are passing a single regex string, not a list
RED_KEYWORDS_PATTERN = re.compile(r"HIGH RISK|DANGEROUS|PHISHING")
YELLOW_KEYWORDS_PATTERN = re.compile(r"SUSPICIOUS|VERIFY|URGENCY|IMPERSONATION")

# Fallback recommendation text used by generate_recommendations when no
# specific threat condition is matched.  Defined at module level so the alert
# facade can re-export it and tests can reference it without hardcoding the
# string in two places.
DEFAULT_CLEAN_RECOMMENDATION = "✅ No issues detected"


def generate_recommendations(
    spam_result: SpamAnalysisResult,
    nlp_result: NLPAnalysisResult,
    media_result: MediaAnalysisResult,
) -> List[str]:
    """Generate actionable recommendations based on threat analysis results."""
    recommendations = []

    # High-risk recommendations
    if spam_result.risk_level == "high":
        recommendations.append("⚠️ HIGH RISK: Move to spam folder immediately")

    if nlp_result.social_engineering_indicators:
        recommendations.append(
            "🎣 Potential phishing: Do not click links or provide credentials"
        )

    if media_result.file_type_warnings:
        recommendations.append(
            "📎 Dangerous attachment detected: Do not open attachments"
        )

    # Medium-risk recommendations
    if spam_result.suspicious_urls:
        recommendations.append(
            "🔗 Suspicious URLs detected: Verify links before clicking"
        )

    if nlp_result.authority_impersonation:
        recommendations.append(
            "👤 Authority impersonation suspected: Verify sender identity"
        )

    if nlp_result.urgency_markers:
        recommendations.append(
            "⏰ Urgency tactics detected: Take time to verify before acting"
        )

    # General recommendations
    if not recommendations:
        recommendations.append(DEFAULT_CLEAN_RECOMMENDATION)

    return recommendations
