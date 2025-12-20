"""
Alert and Response System
Handles threat notifications and alerting across multiple channels
"""

import logging
import json
import requests
from typing import Dict, List
from dataclasses import dataclass, asdict
from datetime import datetime

from ..utils.sanitization import sanitize_for_logging
from .email_ingestion import EmailData
from .spam_analyzer import SpamAnalysisResult
from .nlp_analyzer import NLPAnalysisResult
from .media_analyzer import MediaAnalysisResult
from ..utils.colors import Colors


@dataclass
class ThreatReport:
    """Comprehensive threat report"""
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


class AlertSystem:
    """Manages alerts and notifications"""
    
    def __init__(self, config):
        """
        Initialize alert system
        
        Args:
            config: AlertConfig object
        """
        self.config = config
        self.logger = logging.getLogger("AlertSystem")
    
    def send_alert(self, threat_report: ThreatReport):
        """
        Send alert through configured channels
        
        Args:
            threat_report: Threat report to alert on
        """
        # Only alert on significant threats
        if threat_report.overall_threat_score < self.config.threat_low:
            self.logger.debug(f"Threat score too low to alert: {threat_report.overall_threat_score}")
            return
        
        # Console alert
        if self.config.console:
            self._console_alert(threat_report)
        
        # Webhook alert
        if self.config.webhook_enabled and self.config.webhook_url:
            self._webhook_alert(threat_report)
        
        # Slack alert
        if self.config.slack_enabled and self.config.slack_webhook:
            self._slack_alert(threat_report)
    
    def _console_alert(self, report: ThreatReport):
        """Print alert to console"""
        risk_color = Colors.get_risk_color(report.risk_level)
        header_bar = Colors.colorize("="*80, risk_color)
        
        print("\n" + header_bar)
        print(Colors.colorize(f"🚨 SECURITY ALERT - {report.risk_level.upper()} RISK", risk_color + Colors.BOLD))
        print(header_bar)

        print(f"{Colors.BOLD}Timestamp:{Colors.RESET} {report.timestamp}")
        print(f"{Colors.BOLD}Subject:{Colors.RESET}   {self._sanitize_text(report.subject)}")
        print(f"{Colors.BOLD}From:{Colors.RESET}      {self._sanitize_text(report.sender)}")
        print(f"{Colors.BOLD}To:{Colors.RESET}        {self._sanitize_text(report.recipient)}")
        print(f"{Colors.BOLD}Score:{Colors.RESET}     {report.overall_threat_score:.2f}")
        print(f"{Colors.BOLD}Risk:{Colors.RESET}      {Colors.colorize(report.risk_level.upper(), risk_color + Colors.BOLD)}")

        print(f"\n{Colors.BOLD}--- SPAM ANALYSIS ---{Colors.RESET}")
        spam = report.spam_analysis
        if spam.get('indicators'):
            for indicator in spam['indicators'][:5]:  # Show first 5
                print(f"  {Colors.colorize('•', Colors.CYAN)} {indicator}")
        
        print(f"\n{Colors.BOLD}--- NLP THREAT ANALYSIS ---{Colors.RESET}")
        nlp = report.nlp_analysis
        if nlp.get('social_engineering_indicators'):
            print(f"  {Colors.BOLD}Social Engineering:{Colors.RESET}")
            for indicator in nlp['social_engineering_indicators'][:3]:
                print(f"    {Colors.colorize('•', Colors.RED)} {indicator}")
        if nlp.get('authority_impersonation'):
            print(f"  {Colors.BOLD}Authority Impersonation:{Colors.RESET}")
            for indicator in nlp['authority_impersonation'][:3]:
                print(f"    {Colors.colorize('•', Colors.RED)} {indicator}")
        
        print(f"\n{Colors.BOLD}--- MEDIA ANALYSIS ---{Colors.RESET}")
        media = report.media_analysis
        if media.get('file_type_warnings'):
            print(f"  {Colors.BOLD}File Warnings:{Colors.RESET}")
            for warning in media['file_type_warnings'][:3]:
                print(f"    {Colors.colorize('•', Colors.YELLOW)} {warning}")
        
        print(f"\n{Colors.BOLD}--- RECOMMENDATIONS ---{Colors.RESET}")
        for rec in report.recommendations:
            print(f"  {Colors.colorize('►', Colors.GREEN)} {rec}")
        
        print(header_bar + "\n")
    
    def _webhook_alert(self, report: ThreatReport):
        """Send alert via webhook"""
        try:
            payload = asdict(report)
            response = requests.post(
                self.config.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Webhook alert sent successfully")
            else:
                self.logger.warning(f"Webhook alert failed: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
    
    def _sanitize_text(self, text: str) -> str:
        """
        Sanitize text for safe console output.
        Removes control characters and normalizes whitespace.
        """
        if not text:
            return ""

        # Replace newlines and tabs with spaces
        sanitized = text.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')

        # Remove control characters (0x00-0x1F and 0x7F-0x9F), preserve printable Unicode
        sanitized = ''.join(
            c for c in sanitized
            if not (
                (0 <= ord(c) <= 31) or
                (127 <= ord(c) <= 159)
            )
        )

        return sanitized

    def _sanitize_for_slack(self, text: str) -> str:
        """
        Sanitize text for Slack to prevent injection and spoofing.
        Escapes &, <, > and sanitizes control characters.
        """
        if not text:
            return ""

        # First sanitize control characters using the existing method
        text = self._sanitize_text(text)

        # Escape Slack special characters
        # Reference: https://api.slack.com/reference/surfaces/formatting#escaping
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def _slack_alert(self, report: ThreatReport):
        """Send alert to Slack"""
        try:
            # Format Slack message
            color = {
                "low": "#36a64f",
                "medium": "#ff9900",
                "high": "#ff0000"
            }.get(report.risk_level, "#808080")
            
            attachments = [{
                "color": color,
                "title": f"🚨 Security Alert - {report.risk_level.upper()} Risk",
                "fields": [
                    {
                        "title": "Subject",
                        "value": self._sanitize_for_slack(report.subject),
                        "short": False
                    },
                    {
                        "title": "From",
                        "value": self._sanitize_for_slack(report.sender),
                        "short": True
                    },
                    {
                        "title": "Threat Score",
                        "value": f"{report.overall_threat_score:.2f}",
                        "short": True
                    },
                    {
                        "title": "Top Recommendation",
                        "value": report.recommendations[0] if report.recommendations else "Review email",
                        "short": False
                    }
                ],
                "footer": "Email Security Pipeline",
                "ts": int(datetime.now().timestamp())
            }]
            
            payload = {
                "text": "New email security threat detected",
                "attachments": attachments
            }
            
            response = requests.post(
                self.config.slack_webhook,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Slack alert sent successfully")
            else:
                self.logger.warning(f"Slack alert failed: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")


def generate_threat_report(
    email_data: EmailData,
    spam_result: SpamAnalysisResult,
    nlp_result: NLPAnalysisResult,
    media_result: MediaAnalysisResult
) -> ThreatReport:
    """
    Generate comprehensive threat report
    
    Args:
        email_data: Email data
        spam_result: Spam analysis result
        nlp_result: NLP analysis result
        media_result: Media analysis result
        
    Returns:
        ThreatReport
    """
    # Calculate overall threat score
    overall_score = (
        spam_result.score +
        nlp_result.threat_score +
        media_result.threat_score
    )
    
    # Determine overall risk level
    if spam_result.risk_level == "high" or nlp_result.risk_level == "high" or media_result.risk_level == "high":
        risk_level = "high"
    elif spam_result.risk_level == "medium" or nlp_result.risk_level == "medium" or media_result.risk_level == "medium":
        risk_level = "medium"
    else:
        risk_level = "low"
    
    # Generate recommendations
    recommendations = _generate_recommendations(spam_result, nlp_result, media_result)
    
    return ThreatReport(
        email_id=email_data.message_id,
        subject=email_data.subject,
        sender=email_data.sender,
        recipient=email_data.recipient,
        date=email_data.date.isoformat(),
        overall_threat_score=overall_score,
        risk_level=risk_level,
        spam_analysis={
            'score': spam_result.score,
            'risk_level': spam_result.risk_level,
            'indicators': spam_result.indicators,
            'suspicious_urls': spam_result.suspicious_urls,
            'header_issues': spam_result.header_issues
        },
        nlp_analysis={
            'score': nlp_result.threat_score,
            'risk_level': nlp_result.risk_level,
            'social_engineering_indicators': nlp_result.social_engineering_indicators,
            'urgency_markers': nlp_result.urgency_markers,
            'authority_impersonation': nlp_result.authority_impersonation,
            'psychological_triggers': nlp_result.psychological_triggers
        },
        media_analysis={
            'score': media_result.threat_score,
            'risk_level': media_result.risk_level,
            'suspicious_attachments': media_result.suspicious_attachments,
            'file_type_warnings': media_result.file_type_warnings,
            'size_anomalies': media_result.size_anomalies,
            'potential_deepfakes': media_result.potential_deepfakes
        },
        recommendations=recommendations,
        timestamp=datetime.now().isoformat()
    )


def _generate_recommendations(
    spam_result: SpamAnalysisResult,
    nlp_result: NLPAnalysisResult,
    media_result: MediaAnalysisResult
) -> List[str]:
    """Generate actionable recommendations"""
    recommendations = []
    
    # High-risk recommendations
    if spam_result.risk_level == "high":
        recommendations.append("⚠️ HIGH RISK: Move to spam folder immediately")
    
    if nlp_result.social_engineering_indicators:
        recommendations.append("🎣 Potential phishing: Do not click links or provide credentials")
    
    if media_result.file_type_warnings:
        recommendations.append("📎 Dangerous attachment detected: Do not open attachments")
    
    # Medium-risk recommendations
    if spam_result.suspicious_urls:
        recommendations.append("🔗 Suspicious URLs detected: Verify links before clicking")
    
    if nlp_result.authority_impersonation:
        recommendations.append("👤 Authority impersonation suspected: Verify sender identity")
    
    if nlp_result.urgency_markers:
        recommendations.append("⏰ Urgency tactics detected: Take time to verify before acting")
    
    # General recommendations
    if not recommendations:
        recommendations.append("Review email carefully before taking action")
    
    return recommendations
