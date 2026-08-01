"""
Threat report generation.

Aggregates per-layer analysis results into a comprehensive, serializable report.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

from .alert_recommendations import generate_recommendations
from .email_data import EmailData
from .media_analyzer import MediaAnalysisResult
from .nlp_analyzer import NLPAnalysisResult
from .spam_analyzer import SpamAnalysisResult


@dataclass
class ThreatReport:
    """Comprehensive threat report."""

    email_id: str
    subject: str
    sender: str
    recipient: str
    date: str
    overall_threat_score: float
    risk_level: str
    spam_analysis: Dict
    nlp_analysis: Dict
    media_analysis: Dict
    recommendations: List[str]
    timestamp: str


@dataclass
class RenderConfig:
    """Configuration options for console rendering."""

    width: int
    risk_color: str
    risk_symbol: str


def _calculate_overall_risk_level(
    spam_result: SpamAnalysisResult,
    nlp_result: NLPAnalysisResult,
    media_result: MediaAnalysisResult,
) -> str:
    """Calculate overall risk level from individual analysis results."""
    risk_levels = [
        spam_result.risk_level,
        nlp_result.risk_level,
        media_result.risk_level,
    ]

    if "high" in risk_levels:
        return "high"
    if "medium" in risk_levels:
        return "medium"
    return "low"


def _build_spam_analysis_dict(spam_result: SpamAnalysisResult) -> Dict:
    """Build spam analysis dictionary for threat report."""
    return {
        "score": spam_result.score,
        "risk_level": spam_result.risk_level,
        "indicators": spam_result.indicators,
        "suspicious_urls": spam_result.suspicious_urls,
        "header_issues": spam_result.header_issues,
    }


def _build_nlp_analysis_dict(nlp_result: NLPAnalysisResult) -> Dict:
    """Build NLP analysis dictionary for threat report."""
    return {
        "score": nlp_result.threat_score,
        "risk_level": nlp_result.risk_level,
        "social_engineering_indicators": nlp_result.social_engineering_indicators,
        "urgency_markers": nlp_result.urgency_markers,
        "authority_impersonation": nlp_result.authority_impersonation,
        "psychological_triggers": nlp_result.psychological_triggers,
    }


def _build_media_analysis_dict(media_result: MediaAnalysisResult) -> Dict:
    """Build media analysis dictionary for threat report."""
    return {
        "score": media_result.threat_score,
        "risk_level": media_result.risk_level,
        "suspicious_attachments": media_result.suspicious_attachments,
        "file_type_warnings": media_result.file_type_warnings,
        "size_anomalies": media_result.size_anomalies,
        "potential_deepfakes": media_result.potential_deepfakes,
    }


def generate_threat_report(
    email_data: EmailData,
    spam_result: SpamAnalysisResult,
    nlp_result: NLPAnalysisResult,
    media_result: MediaAnalysisResult,
) -> ThreatReport:
    """
    Generate comprehensive threat report.

    Args:
        email_data: Email data
        spam_result: Spam analysis result
        nlp_result: NLP analysis result
        media_result: Media analysis result

    Returns:
        ThreatReport

    """
    overall_score = (
        spam_result.score + nlp_result.threat_score + media_result.threat_score
    )
    risk_level = _calculate_overall_risk_level(spam_result, nlp_result, media_result)
    recommendations = generate_recommendations(spam_result, nlp_result, media_result)

    return ThreatReport(
        email_id=email_data.message_id,
        subject=email_data.subject,
        sender=email_data.sender,
        recipient=email_data.recipient,
        date=email_data.date.isoformat(),
        overall_threat_score=overall_score,
        risk_level=risk_level,
        spam_analysis=_build_spam_analysis_dict(spam_result),
        nlp_analysis=_build_nlp_analysis_dict(nlp_result),
        media_analysis=_build_media_analysis_dict(media_result),
        recommendations=recommendations,
        timestamp=datetime.now().isoformat(),
    )
