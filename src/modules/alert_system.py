"""
Alert and Response System
Handles threat notifications and alerting across multiple channels
"""

import logging
import json
import re
import requests
from typing import Dict, List
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..utils.sanitization import sanitize_for_logging, sanitize_for_csv
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
            # Provide positive feedback for clean emails if console is enabled
            if self.config.console:
                self._console_clean_report(threat_report)
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
        
        # Format timestamp nicely
        try:
            dt = datetime.fromisoformat(report.timestamp)
            formatted_time = dt.strftime("%b %d, %Y at %H:%M:%S")
        except ValueError:
            formatted_time = report.timestamp

        print("\n" + header_bar)
        print(Colors.colorize(f"🚨 SECURITY ALERT - {report.risk_level.upper()} RISK", risk_color + Colors.BOLD))
        print(header_bar)

        print(f"{Colors.BOLD}Timestamp:{Colors.RESET} {formatted_time}")
        print(f"{Colors.BOLD}Subject:{Colors.RESET}   {self._sanitize_text(report.subject, csv_safe=True)}")
        print(f"{Colors.BOLD}From:{Colors.RESET}      {self._sanitize_text(report.sender, csv_safe=True)}")
        print(f"{Colors.BOLD}To:{Colors.RESET}        {self._sanitize_text(report.recipient, csv_safe=True)}")

        # Threat meter
        score_val = min(max(report.overall_threat_score, 0), 100)
        meter_len = 20
        filled_len = int(score_val / 100 * meter_len)
        bar = "█" * filled_len + "░" * (meter_len - filled_len)
        meter_color = Colors.get_risk_color(report.risk_level)

        risk_symbol = Colors.get_risk_symbol(report.risk_level)
        print(f"{Colors.BOLD}Score:{Colors.RESET}     {Colors.colorize(bar, meter_color)} {report.overall_threat_score:.2f}/100")
        print(
            f"{Colors.BOLD}Risk:{Colors.RESET}      "
            f"{Colors.colorize(report.risk_level.upper(), risk_color + Colors.BOLD)}"
            f" {risk_symbol}"
        )

        # Spam Analysis Section
        print(f"\n{Colors.BOLD}📧 SPAM ANALYSIS{Colors.RESET}")
        spam = report.spam_analysis
        has_spam_indicators = False
        if spam.get('indicators'):
            has_spam_indicators = True
            for indicator in spam['indicators'][:5]:  # Show first 5
                print(f"  {Colors.colorize('•', Colors.CYAN)} {indicator}")
        
        if not has_spam_indicators:
            print(f"  {Colors.colorize('✓', Colors.GREEN)} No suspicious patterns detected")

        # NLP Analysis Section
        print(f"\n{Colors.BOLD}🧠 NLP THREAT ANALYSIS{Colors.RESET}")
        nlp = report.nlp_analysis
        has_nlp_issues = False

        if nlp.get('social_engineering_indicators'):
            has_nlp_issues = True
            print(f"  {Colors.BOLD}Social Engineering:{Colors.RESET}")
            for indicator in nlp['social_engineering_indicators'][:3]:
                print(f"    {Colors.colorize('•', Colors.RED)} {indicator}")

        if nlp.get('authority_impersonation'):
            has_nlp_issues = True
            print(f"  {Colors.BOLD}Authority Impersonation:{Colors.RESET}")
            for indicator in nlp['authority_impersonation'][:3]:
                print(f"    {Colors.colorize('•', Colors.RED)} {indicator}")

        if not has_nlp_issues:
            print(f"  {Colors.colorize('✓', Colors.GREEN)} No psychological triggers or impersonation detected")
        
        # Media Analysis Section
        print(f"\n{Colors.BOLD}📎 MEDIA ANALYSIS{Colors.RESET}")
        media = report.media_analysis
        has_media_issues = False
        if media.get('file_type_warnings'):
            has_media_issues = True
            print(f"  {Colors.BOLD}File Warnings:{Colors.RESET}")
            for warning in media['file_type_warnings'][:3]:
                print(f"    {Colors.colorize('•', Colors.YELLOW)} {warning}")

        if not has_media_issues:
            print(f"  {Colors.colorize('✓', Colors.GREEN)} Attachments appear safe")
        
        print(f"\n{Colors.BOLD}🛡️  RECOMMENDATIONS{Colors.RESET}")
        for rec in report.recommendations:
            color = Colors.GREEN
            rec_upper = rec.upper()
            if any(key in rec_upper for key in ["HIGH RISK", "DANGEROUS", "PHISHING"]):
                color = Colors.RED
            elif any(key in rec_upper for key in ["SUSPICIOUS", "VERIFY", "URGENCY", "IMPERSONATION"]):
                color = Colors.YELLOW
            print(f"  {Colors.colorize('►', color)} {rec}")
        
        print(header_bar + "\n")
    
    def _console_clean_report(self, report: ThreatReport):
        """Print clean report to console"""
        # Compact format for clean emails
        score_val = max(0.0, report.overall_threat_score)

        # Calculate risk relative to the low threshold (the "clean" budget)
        threshold = self.config.threat_low
        if threshold <= 0: threshold = 30

        percent_of_threshold = min(score_val / threshold, 1.0)

        # Mini bar: 10 chars
        bar_len = 10
        filled = int(percent_of_threshold * bar_len)

        # Bar construction
        fill_char = "■"
        empty_char = "·"

        filled_part = fill_char * filled
        empty_part = empty_char * (bar_len - filled)

        # Color logic
        bar_color = Colors.GREEN
        if percent_of_threshold > 0.6:
            bar_color = Colors.YELLOW

        colored_filled = Colors.colorize(filled_part, bar_color)
        colored_empty = Colors.colorize(empty_part, Colors.GREY)

        visual_bar = f"[{colored_filled}{colored_empty}]"

        # Short timestamp
        try:
            dt = datetime.fromisoformat(report.timestamp)
            time_str = dt.strftime("%H:%M:%S")
        except ValueError:
            time_str = report.timestamp

        # Subject truncated
        sanitized_subject = self._sanitize_text(report.subject)
        subject = sanitized_subject[:50]
        if len(sanitized_subject) > 50:
            subject += "..."

        # Separator
        sep = Colors.colorize("│", Colors.GREY)

        # Format:
        # ✓ CLEAN | HH:MM:SS | Score: XX.X [■■···] | Subject
        print(
            f"{Colors.GREEN}✓ CLEAN{Colors.RESET} "
            f"{sep} {time_str} "
            f"{sep} Score: {score_val:4.1f} {visual_bar} "
            f"{sep} {subject}"
        )

    def _webhook_alert(self, report: ThreatReport):
        """Send alert via webhook"""
        try:
            payload = asdict(report)

            # Redact sensitive info from suspicious URLs if present
            if 'spam_analysis' in payload and 'suspicious_urls' in payload['spam_analysis']:
                urls = payload['spam_analysis']['suspicious_urls']
                if urls:
                    payload['spam_analysis']['suspicious_urls'] = [
                        self._redact_sensitive_url_params(url) for url in urls
                    ]

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
            self.logger.error(f"Failed to send webhook alert: {self._sanitize_error_message(e)}")

    def _sanitize_error_message(self, error: Exception) -> str:
        """
        Sanitize exception messages to prevent leaking sensitive URLs/tokens.
        Detects URLs in the error message and redacts them.
        """
        msg = str(error)
        try:
            # Find all URLs in the message
            # Simple regex for http/https URLs to catch full URLs including query params
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', msg)

            for url in urls:
                # Clean up trailing punctuation that might have been matched
                clean_url = url.rstrip('.,;:)\'')

                # Apply redaction
                redacted = self._redact_url_secrets(clean_url)

                # If redaction changed anything, update the message
                if redacted != clean_url:
                    msg = msg.replace(clean_url, redacted)

            return msg
        except Exception:
            return "An error occurred (details redacted for security)"
    
    def _redact_url_secrets(self, url: str) -> str:
        """
        Redact sensitive information from URL (query params and specific paths).
        Handles Slack/Discord webhooks and sensitive query parameters.
        """
        try:
            if not url:
                return ""

            # 1. Redact sensitive query parameters (reusing logic)
            url = self._redact_sensitive_url_params(url)

            parsed = urlparse(url)

            # 2. Redact Slack Webhooks
            # Format: /services/T000/B000/TOKEN
            netloc = parsed.netloc.lower()
            if (netloc == "hooks.slack.com" or netloc.endswith(".slack.com")) and parsed.path.startswith("/services/"):
                parts = parsed.path.split('/')
                # parts[0] is empty, parts[1] is 'services'
                # parts[2] is Team ID, parts[3] is Bot ID, parts[4] is Token
                # We redact the token (last part)
                if len(parts) >= 5:
                    parts[-1] = "[REDACTED]"
                    new_path = "/".join(parts)
                    parsed = parsed._replace(path=new_path)
                    return urlunparse(parsed)

            # 3. Redact Discord Webhooks
            # Format: /api/webhooks/ID/TOKEN
            if (netloc == "discord.com" or netloc.endswith(".discord.com")) and parsed.path.startswith("/api/webhooks/"):
                parts = parsed.path.split('/')
                # parts[-1] is likely the token
                if len(parts) >= 5:
                    parts[-1] = "[REDACTED]"
                    new_path = "/".join(parts)
                    parsed = parsed._replace(path=new_path)
                    return urlunparse(parsed)

            return url
        except Exception:
            return url

    def _redact_sensitive_url_params(self, url: str) -> str:
        """
        Redact sensitive query parameters from URL.
        Prevents leaking credentials or tokens in logs/alerts.
        """
        try:
            if not url:
                return ""

            parsed = urlparse(url)
            # keep_blank_values=True ensures we don't drop empty params
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            sensitive_keys = {
                'password', 'token', 'secret', 'key', 'apikey', 'api_key',
                'access_token', 'auth', 'authorization', 'sig', 'signature'
            }

            changed = False
            for key in query_params:
                if key.lower() in sensitive_keys:
                    query_params[key] = ['[REDACTED]']
                    changed = True

            if changed:
                # doseq=True handles lists of values correctly
                new_query = urlencode(query_params, doseq=True)
                parsed = parsed._replace(query=new_query)
                return urlunparse(parsed)
            return url
        except Exception:
            # If parsing fails, return original to avoid losing data,
            # but rely on other sanitization layers if any.
            return url

    def _sanitize_text(self, text: str, csv_safe: bool = False) -> str:
        """
        Sanitize text for safe console output.
        Removes control characters and normalizes whitespace.

        Args:
            text: Input text
            csv_safe: If True, applies CSV/Formula injection prevention
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

        if csv_safe:
            # Prevent Formula/CSV Injection for console logs that might be exported
            sanitized = sanitize_for_csv(sanitized)

        return sanitized

    def _sanitize_for_slack(self, text: str) -> str:
        """
        Sanitize text for Slack to prevent injection and spoofing.
        Escapes &, <, > and sanitizes control characters.
        """
        if not text:
            return ""

        # First sanitize control characters using the existing method
        # We do NOT use csv_safe=True here to avoid messing up Slack formatting
        text = self._sanitize_text(text, csv_safe=False)

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
            self.logger.error(f"Failed to send Slack alert: {self._sanitize_error_message(e)}")


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
