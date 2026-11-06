"""Unit tests for src/modules/alert_report.py."""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from src.modules.alert_report import (
    RenderConfig,
    ThreatReport,
    _build_media_analysis_dict,
    _build_nlp_analysis_dict,
    _build_spam_analysis_dict,
    _calculate_overall_risk_level,
    generate_threat_report,
)
from src.modules.email_data import EmailData
from src.modules.media_analyzer import MediaAnalysisResult
from src.modules.nlp_analyzer import NLPAnalysisResult
from src.modules.spam_analyzer import SpamAnalysisResult


class TestAlertReport(unittest.TestCase):
    """Test suite for alert report dataclasses and helper functions."""

    def setUp(self):
        self.email_data = EmailData(
            message_id="msg-999",
            subject="Urgent Invoice",
            sender="billing@example.org",
            recipient="user@example.com",
            account_email="user@example.com",
            folder="INBOX",
            date=datetime(2025, 5, 10, 14, 30, 0, tzinfo=timezone.utc),
            body_text="Please find the attached invoice.",
            body_html="<p>Please find the attached invoice.</p>",
            headers={"From": "billing@example.org"},
            raw_email=MagicMock(),
            attachments=["invoice.pdf"],
        )

        self.spam_result = SpamAnalysisResult(
            score=15.5,
            indicators=["suspicious_sender"],
            suspicious_urls=["https://phishing.example.com"],
            header_issues=["spf_fail"],
            risk_level="high",
        )

        self.nlp_result = NLPAnalysisResult(
            threat_score=8.0,
            social_engineering_indicators=["urgency_demand"],
            urgency_markers=["immediate_action"],
            authority_impersonation=["billing_department"],
            psychological_triggers=["fear_of_penalty"],
            risk_level="medium",
        )

        self.media_result = MediaAnalysisResult(
            threat_score=4.5,
            suspicious_attachments=["invoice.pdf.exe"],
            file_type_warnings=["executable_extension"],
            size_anomalies=["size_mismatch"],
            potential_deepfakes=["voice_artifact"],
            risk_level="low",
        )

    def test_render_config_instantiation(self):
        """Test RenderConfig dataclass initialization and attributes."""
        config = RenderConfig(width=100, risk_color="red", risk_symbol="[x]")
        self.assertEqual(config.width, 100)
        self.assertEqual(config.risk_color, "red")
        self.assertEqual(config.risk_symbol, "[x]")

    def test_threat_report_instantiation(self):
        """Test ThreatReport dataclass initialization and fields."""
        report = ThreatReport(
            email_id="123",
            subject="Test",
            sender="a@b.com",
            recipient="c@d.com",
            date="2025-01-01T00:00:00",
            overall_threat_score=28.0,
            risk_level="high",
            spam_analysis={"score": 15.5},
            nlp_analysis={"score": 8.0},
            media_analysis={"score": 4.5},
            recommendations=["Do not open attachments"],
            timestamp="2025-01-01T00:00:01",
        )
        self.assertEqual(report.email_id, "123")
        self.assertEqual(report.overall_threat_score, 28.0)
        self.assertEqual(report.risk_level, "high")
        self.assertEqual(len(report.recommendations), 1)

    def test_calculate_overall_risk_level_high_priority(self):
        """High risk takes precedence over medium and low across layers."""
        self.assertEqual(
            _calculate_overall_risk_level(self.spam_result, self.nlp_result, self.media_result),
            "high",
        )

    def test_calculate_overall_risk_level_medium_priority(self):
        """Medium risk takes precedence when no layer is high."""
        spam_low = SpamAnalysisResult(
            score=1.0, indicators=[], suspicious_urls=[], header_issues=[], risk_level="low"
        )
        media_low = MediaAnalysisResult(
            threat_score=1.0, suspicious_attachments=[], file_type_warnings=[], size_anomalies=[], potential_deepfakes=[], risk_level="low"
        )
        self.assertEqual(
            _calculate_overall_risk_level(spam_low, self.nlp_result, media_low),
            "medium",
        )

    def test_calculate_overall_risk_level_low(self):
        """Returns low only when all layers are low."""
        spam_low = SpamAnalysisResult(
            score=1.0, indicators=[], suspicious_urls=[], header_issues=[], risk_level="low"
        )
        nlp_low = NLPAnalysisResult(
            threat_score=1.0, social_engineering_indicators=[], urgency_markers=[], authority_impersonation=[], psychological_triggers=[], risk_level="low"
        )
        media_low = MediaAnalysisResult(
            threat_score=1.0, suspicious_attachments=[], file_type_warnings=[], size_anomalies=[], potential_deepfakes=[], risk_level="low"
        )
        self.assertEqual(
            _calculate_overall_risk_level(spam_low, nlp_low, media_low),
            "low",
        )

    def test_build_spam_analysis_dict(self):
        """Verify dictionary structure and keys built from SpamAnalysisResult."""
        data = _build_spam_analysis_dict(self.spam_result)
        self.assertEqual(
            data,
            {
                "score": 15.5,
                "risk_level": "high",
                "indicators": ["suspicious_sender"],
                "suspicious_urls": ["https://phishing.example.com"],
                "header_issues": ["spf_fail"],
            },
        )

    def test_build_nlp_analysis_dict(self):
        """Verify dictionary structure and keys built from NLPAnalysisResult."""
        data = _build_nlp_analysis_dict(self.nlp_result)
        self.assertEqual(
            data,
            {
                "score": 8.0,
                "risk_level": "medium",
                "social_engineering_indicators": ["urgency_demand"],
                "urgency_markers": ["immediate_action"],
                "authority_impersonation": ["billing_department"],
                "psychological_triggers": ["fear_of_penalty"],
            },
        )

    def test_build_media_analysis_dict(self):
        """Verify dictionary structure and keys built from MediaAnalysisResult."""
        data = _build_media_analysis_dict(self.media_result)
        self.assertEqual(
            data,
            {
                "score": 4.5,
                "risk_level": "low",
                "suspicious_attachments": ["invoice.pdf.exe"],
                "file_type_warnings": ["executable_extension"],
                "size_anomalies": ["size_mismatch"],
                "potential_deepfakes": ["voice_artifact"],
            },
        )

    @patch("src.modules.alert_report.generate_recommendations")
    def test_generate_threat_report_comprehensive(self, mock_generate_recommendations):
        """Verify threat report generation aggregates all scores and maps fields properly."""
        mock_generate_recommendations.return_value = ["Verify invoice authenticity"]

        report = generate_threat_report(
            self.email_data,
            self.spam_result,
            self.nlp_result,
            self.media_result,
        )

        mock_generate_recommendations.assert_called_once_with(
            self.spam_result, self.nlp_result, self.media_result
        )

        self.assertEqual(report.email_id, "msg-999")
        self.assertEqual(report.subject, "Urgent Invoice")
        self.assertEqual(report.sender, "billing@example.org")
        self.assertEqual(report.recipient, "user@example.com")
        self.assertEqual(report.date, "2025-05-10T14:30:00+00:00")
        self.assertAlmostEqual(report.overall_threat_score, 15.5 + 8.0 + 4.5)
        self.assertEqual(report.risk_level, "high")
        self.assertEqual(report.recommendations, ["Verify invoice authenticity"])

        # Timestamp should be parseable ISO format
        parsed_ts = datetime.fromisoformat(report.timestamp)
        self.assertIsInstance(parsed_ts, datetime)


if __name__ == "__main__":
    unittest.main()
