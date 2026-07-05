import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.alert_system import generate_threat_report, ThreatReport
from src.modules.email_ingestion import EmailData
from src.modules.spam_analyzer import SpamAnalysisResult
from src.modules.nlp_analyzer import NLPAnalysisResult
from src.modules.media_analyzer import MediaAnalysisResult


class TestGenerateThreatReport(unittest.TestCase):
    def setUp(self):
        self.email_data = EmailData(
            message_id="msg-123",
            subject="Test Subject",
            sender="sender@example.com",
            recipient="recipient@example.com",
            account_email="account@example.com",
            folder="INBOX",
            date=datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            body_text="Test body",
            body_html="",
            headers={},
            raw_email=MagicMock(),
            attachments=[],
        )

        self.spam_result_low = SpamAnalysisResult(
            score=10.0,
            indicators=["spam_indicator_1"],
            suspicious_urls=["http://spam.com"],
            header_issues=["header_issue_1"],
            risk_level="low",
        )

        self.nlp_result_low = NLPAnalysisResult(
            threat_score=5.0,
            social_engineering_indicators=["soc_eng_1"],
            urgency_markers=["urgency_1"],
            authority_impersonation=["auth_1"],
            psychological_triggers=["psych_1"],
            risk_level="low",
        )

        self.media_result_low = MediaAnalysisResult(
            threat_score=2.0,
            suspicious_attachments=["att_1"],
            file_type_warnings=["file_warn_1"],
            size_anomalies=["size_1"],
            potential_deepfakes=["deepfake_1"],
            risk_level="low",
        )

    @patch("src.modules.alert_system.AlertSystem._generate_recommendations")
    def test_generate_threat_report_low_risk(self, mock_generate_recommendations):
        mock_generate_recommendations.return_value = ["mocked recommendation"]

        report = generate_threat_report(
            self.email_data,
            self.spam_result_low,
            self.nlp_result_low,
            self.media_result_low,
        )

        self.assertIsInstance(report, ThreatReport)
        self.assertEqual(report.email_id, "msg-123")
        self.assertEqual(report.subject, "Test Subject")
        self.assertEqual(report.sender, "sender@example.com")
        self.assertEqual(report.recipient, "recipient@example.com")
        self.assertEqual(report.date, "2023-01-01T12:00:00+00:00")

        self.assertEqual(report.overall_threat_score, 17.0)  # 10.0 + 5.0 + 2.0
        self.assertEqual(report.risk_level, "low")

        # Verify spam analysis data
        self.assertEqual(report.spam_analysis["score"], 10.0)
        self.assertEqual(report.spam_analysis["risk_level"], "low")
        self.assertEqual(report.spam_analysis["indicators"], ["spam_indicator_1"])
        self.assertEqual(report.spam_analysis["suspicious_urls"], ["http://spam.com"])
        self.assertEqual(report.spam_analysis["header_issues"], ["header_issue_1"])

        # Verify NLP analysis data
        self.assertEqual(report.nlp_analysis["score"], 5.0)
        self.assertEqual(report.nlp_analysis["risk_level"], "low")
        self.assertEqual(
            report.nlp_analysis["social_engineering_indicators"], ["soc_eng_1"]
        )
        self.assertEqual(report.nlp_analysis["urgency_markers"], ["urgency_1"])
        self.assertEqual(report.nlp_analysis["authority_impersonation"], ["auth_1"])
        self.assertEqual(report.nlp_analysis["psychological_triggers"], ["psych_1"])

        # Verify media analysis data
        self.assertEqual(report.media_analysis["score"], 2.0)
        self.assertEqual(report.media_analysis["risk_level"], "low")
        self.assertEqual(report.media_analysis["suspicious_attachments"], ["att_1"])
        self.assertEqual(report.media_analysis["file_type_warnings"], ["file_warn_1"])
        self.assertEqual(report.media_analysis["size_anomalies"], ["size_1"])
        self.assertEqual(report.media_analysis["potential_deepfakes"], ["deepfake_1"])

        self.assertEqual(report.recommendations, ["mocked recommendation"])
        self.assertIsInstance(report.timestamp, str)

        mock_generate_recommendations.assert_called_once_with(
            self.spam_result_low, self.nlp_result_low, self.media_result_low
        )

    def _create_analysis_result(self, result_type, risk_level, score):
        if result_type == "spam":
            return SpamAnalysisResult(
                score=score,
                indicators=[],
                suspicious_urls=[],
                header_issues=[],
                risk_level=risk_level,
            )
        elif result_type == "nlp":
            return NLPAnalysisResult(
                threat_score=score,
                social_engineering_indicators=[],
                urgency_markers=[],
                authority_impersonation=[],
                psychological_triggers=[],
                risk_level=risk_level,
            )
        else:
            return MediaAnalysisResult(
                threat_score=score,
                suspicious_attachments=[],
                file_type_warnings=[],
                size_anomalies=[],
                potential_deepfakes=[],
                risk_level=risk_level,
            )

    def _get_scenario_score(self, risk_level, default_score):
        if risk_level == "high":
            return 90.0
        elif risk_level == "medium":
            return 50.0
        return default_score

    def test_overall_risk_levels(self):
        scenarios = [
            {
                "name": "high_from_spam",
                "spam_risk": "high",
                "nlp_risk": "low",
                "media_risk": "low",
                "expected": "high",
            },
            {
                "name": "high_from_nlp",
                "spam_risk": "low",
                "nlp_risk": "high",
                "media_risk": "low",
                "expected": "high",
            },
            {
                "name": "high_from_media",
                "spam_risk": "low",
                "nlp_risk": "low",
                "media_risk": "high",
                "expected": "high",
            },
            {
                "name": "medium",
                "spam_risk": "medium",
                "nlp_risk": "low",
                "media_risk": "low",
                "expected": "medium",
            },
            {
                "name": "medium_multiple",
                "spam_risk": "medium",
                "nlp_risk": "medium",
                "media_risk": "low",
                "expected": "medium",
            },
        ]

        for scenario in scenarios:
            with self.subTest(scenario=scenario["name"]):
                spam_score = self._get_scenario_score(scenario["spam_risk"], 10.0)
                nlp_score = self._get_scenario_score(scenario["nlp_risk"], 5.0)
                media_score = self._get_scenario_score(scenario["media_risk"], 2.0)

                spam_result = self._create_analysis_result(
                    "spam", scenario["spam_risk"], spam_score
                )
                nlp_result = self._create_analysis_result(
                    "nlp", scenario["nlp_risk"], nlp_score
                )
                media_result = self._create_analysis_result(
                    "media", scenario["media_risk"], media_score
                )

                report = generate_threat_report(
                    self.email_data, spam_result, nlp_result, media_result
                )
                self.assertEqual(report.risk_level, scenario["expected"])


if __name__ == "__main__":
    unittest.main()
