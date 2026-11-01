"""
Unit tests for src.modules.alert_console.

SECURITY STORY: alert_console formats security alerts and reports directly
for terminal operators and incident responders. Improper sanitisation, unhandled
exceptions in terminal dimension queries, or broken layout logic could cause
crash loops, denial of service, log evasion via malicious ANSI sequences,
or silent failure to display critical threat warnings.
"""

import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.alert_console import (
    _determine_recommendation_color,
    _print_wrapped_lines,
    _strip_recommendation_prefix,
    get_terminal_width,
    get_visual_length,
    print_alert_header,
    print_alert_metadata,
    print_alert_row,
    print_analysis_details,
    print_analysis_section_header,
    print_media_details,
    print_nlp_details,
    print_recommendations,
    print_spam_details,
    print_threat_score,
    render_alert,
    render_clean_report,
    safe_console_url,
    spam_detail_rows,
    spam_header_issue_rows,
    spam_indicator_rows,
    spam_url_rows,
    truncate_text,
)
from src.modules.alert_report import RenderConfig, ThreatReport
from src.utils.colors import Colors


def _make_report(**kwargs) -> ThreatReport:
    """Helper to generate a ThreatReport for testing."""
    defaults = dict(
        email_id="alert-test-001",
        subject="Security Update Required",
        sender="attacker@phish.example",
        recipient="target@company.test",
        date="2026-03-30T12:00:00",
        overall_threat_score=85.0,
        risk_level="high",
        spam_analysis={},
        nlp_analysis={},
        media_analysis={},
        recommendations=[],
        timestamp="2026-03-30T12:00:00",
    )
    defaults.update(kwargs)
    return ThreatReport(**defaults)


class TestGetTerminalWidth(unittest.TestCase):
    """Tests for get_terminal_width fallback and exception handling."""

    def test_default_behavior(self):
        """Standard call returns a positive integer."""
        width = get_terminal_width()
        self.assertIsInstance(width, int)
        self.assertGreaterEqual(width, 1)

    def test_fallback_on_oserror(self):
        """Fallback to 80 on OSError."""
        with patch("shutil.get_terminal_size", side_effect=OSError("Not a tty")):
            self.assertEqual(get_terminal_width(), 80)

    def test_fallback_on_valueerror(self):
        """Fallback to 80 on ValueError."""
        with patch("shutil.get_terminal_size", side_effect=ValueError("Invalid dimensions")):
            self.assertEqual(get_terminal_width(), 80)

    def test_fallback_on_attributeerror(self):
        """Fallback to 80 on AttributeError when shutil lacks get_terminal_size."""
        with patch("shutil.get_terminal_size", side_effect=AttributeError("No get_terminal_size")):
            self.assertEqual(get_terminal_width(), 80)


class TestVisualLengthAndTruncate(unittest.TestCase):
    """Tests for get_visual_length, truncate_text, and safe_console_url."""

    def test_visual_length_empty(self):
        self.assertEqual(get_visual_length(""), 0)

    def test_visual_length_plain(self):
        self.assertEqual(get_visual_length("Clean text"), 10)

    def test_visual_length_ansi(self):
        colored = f"{Colors.RED}Alert{Colors.RESET}"
        self.assertEqual(get_visual_length(colored), 5)

    def test_truncate_text_empty(self):
        self.assertEqual(truncate_text("", 10), "")

    def test_truncate_text_not_needed(self):
        self.assertEqual(truncate_text("Short", 10), "Short")

    def test_truncate_text_boundary_equals_width(self):
        self.assertEqual(truncate_text("ExactLen10", 10), "ExactLen10")

    def test_truncate_text_exceeds_width(self):
        self.assertEqual(truncate_text("Hello World Exceeds", 10), "Hello W...")

    def test_truncate_text_small_widths(self):
        self.assertEqual(truncate_text("Testing", 3), "...")
        self.assertEqual(truncate_text("Testing", 2), "..")
        self.assertEqual(truncate_text("Testing", 1), ".")
        self.assertEqual(truncate_text("Testing", 0), "")

    def test_safe_console_url_redacts_tokens(self):
        raw_url = "https://phish.example/login?token=sensitive_value&user=admin"
        safe = safe_console_url(raw_url)
        self.assertNotIn("sensitive_value", safe)
        self.assertIn("[REDACTED]", safe)


class TestAlertRowAndHeader(unittest.TestCase):
    """Tests for print_alert_row and print_alert_header."""

    def test_print_alert_row(self):
        out = StringIO()
        with patch("sys.stdout", out):
            print_alert_row("Test content", Colors.RED, indent=2)
        printed = out.getvalue()
        self.assertIn("Test content", printed)

    def test_print_alert_header(self):
        cfg = RenderConfig(width=80, risk_color=Colors.RED, risk_symbol="🚨")
        out = StringIO()
        with patch("sys.stdout", out):
            print_alert_header("high", cfg)
        output = out.getvalue()
        self.assertIn("SECURITY ALERT", output)
        self.assertIn("HIGH RISK", output)
        self.assertIn("┌" + "─" * 78 + "┐", output)
        self.assertIn("├" + "─" * 78 + "┤", output)


class TestAlertMetadataAndThreatScore(unittest.TestCase):
    """Tests for print_alert_metadata and print_threat_score."""

    def test_print_alert_metadata_basic(self):
        report = _make_report(subject="Urgent action required", sender="boss@corp.com")
        out = StringIO()
        with patch("sys.stdout", out):
            print_alert_metadata(report, width=80, risk_color=Colors.YELLOW, formatted_time="Mar 30, 2026")
        output = out.getvalue()
        self.assertIn("Timestamp:", output)
        self.assertIn("Mar 30, 2026", output)
        self.assertIn("Subject:", output)
        self.assertIn("Urgent action required", output)
        self.assertIn("From:", output)
        self.assertIn("boss@corp.com", output)

    def test_print_alert_metadata_long_fields_truncated(self):
        long_subject = "A" * 120
        report = _make_report(subject=long_subject)
        out = StringIO()
        with patch("sys.stdout", out):
            print_alert_metadata(report, width=60, risk_color=Colors.RED, formatted_time="Mar 30, 2026")
        output = out.getvalue()
        self.assertIn("...", output)
        self.assertNotIn(long_subject, output)

    def test_print_threat_score_clamping(self):
        out = StringIO()
        with patch("sys.stdout", out), patch("src.utils.colors.Colors.ENABLED", False):
            print_threat_score(120.0, "high", width=70, risk_color="")
            print_threat_score(-15.0, "low", width=70, risk_color="")
        output = out.getvalue()
        self.assertIn("120.00/100", output)
        self.assertIn("-15.00/100", output)


class TestAnalysisDetails(unittest.TestCase):
    """Tests for spam, nlp, and media detail printers."""

    def test_print_analysis_section_header(self):
        out = StringIO()
        with patch("sys.stdout", out):
            print_analysis_section_header("TEST SECTION", {"risk_level": "medium"}, Colors.YELLOW)
        output = out.getvalue()
        self.assertIn("TEST SECTION:", output)
        self.assertIn("MEDIUM", output)

    def test_print_nlp_details_with_findings(self):
        nlp_data = {
            "social_engineering_indicators": ["Urgent gift card request"],
            "urgency_markers": ["Immediate action required"],
            "authority_impersonation": ["Impersonating CEO"],
            "psychological_triggers": ["Fear of account loss"],
        }
        out = StringIO()
        with patch("sys.stdout", out):
            print_nlp_details(nlp_data, risk_color=Colors.RED, max_nlp=2)
        output = out.getvalue()
        self.assertIn("Social Engineering:", output)
        self.assertIn("Urgent gift card request", output)
        self.assertIn("Urgency Markers:", output)
        self.assertIn("Authority Impersonation:", output)
        self.assertIn("Psychological Triggers:", output)

    def test_print_nlp_details_empty_clean(self):
        out = StringIO()
        with patch("sys.stdout", out):
            print_nlp_details({}, risk_color=Colors.GREEN, max_nlp=3)
        output = out.getvalue()
        self.assertIn("No NLP threats detected", output)

    def test_print_media_details_with_warnings(self):
        media_data = {
            "file_type_warnings": ["Executable file extension .exe detected"],
            "suspicious_attachments": ["invoice.zip"],
            "size_anomalies": ["Attachment larger than average"],
            "potential_deepfakes": ["High synthetic artifact confidence"],
        }
        out = StringIO()
        with patch("sys.stdout", out):
            print_media_details(media_data, risk_color=Colors.RED, max_media=2)
        output = out.getvalue()
        self.assertIn("File Warnings:", output)
        self.assertIn("Suspicious Attachments:", output)
        self.assertIn("Size Anomalies:", output)
        self.assertIn("Potential Deepfakes:", output)

    def test_print_media_details_empty_clean(self):
        out = StringIO()
        with patch("sys.stdout", out):
            print_media_details({}, risk_color=Colors.GREEN, max_media=3)
        output = out.getvalue()
        self.assertIn("Attachments appear safe", output)

    def test_spam_detail_rows_helpers(self):
        indicators = spam_indicator_rows(["Pattern matched", "Blacklisted term"], max_spam=1)
        self.assertEqual(len(indicators), 1)

        headers = spam_header_issue_rows(["DKIM failed", "SPF softfail"], max_header=2)
        self.assertEqual(len(headers), 3)  # Title + 2 items

        urls = spam_url_rows(["https://evil.test/login?token=abc"], max_urls=1)
        self.assertEqual(len(urls), 2)  # Title + 1 item
        self.assertIn("[REDACTED]", urls[1][0])

        rows = spam_detail_rows(
            {
                "indicators": ["Ind1"],
                "header_issues": ["Head1"],
                "suspicious_urls": ["https://evil.test"],
            },
            max_spam=2,
            max_header=2,
            max_urls=2,
        )
        self.assertEqual(len(rows), 5)  # 1 indicator + (1 header title + 1 item) + (1 url title + 1 item)

    def test_print_spam_details_empty_and_populated(self):
        out_empty = StringIO()
        with patch("sys.stdout", out_empty):
            print_spam_details({}, Colors.GREEN, {})
        self.assertIn("No suspicious patterns", out_empty.getvalue())

        out_pop = StringIO()
        with patch("sys.stdout", out_pop):
            print_spam_details(
                {"indicators": ["Suspicious keyword"]},
                Colors.RED,
                {"MAX_SPAM_INDICATORS_DISPLAY": 2},
            )
        self.assertIn("Suspicious keyword", out_pop.getvalue())

    def test_print_analysis_details_full(self):
        report = _make_report(
            spam_analysis={"risk_level": "high", "indicators": ["Phishing spam"]},
            nlp_analysis={"risk_level": "medium", "urgency_markers": ["Urgent"]},
            media_analysis={"risk_level": "low"},
        )
        out = StringIO()
        with patch("sys.stdout", out):
            print_analysis_details(report, width=80, risk_color=Colors.RED, limits={})
        output = out.getvalue()
        self.assertIn("ANALYSIS DETAILS", output)
        self.assertIn("SPAM", output)
        self.assertIn("NLP", output)
        self.assertIn("MEDIA", output)


class TestRecommendations(unittest.TestCase):
    """Tests for recommendation helpers and print_recommendations."""

    def test_strip_recommendation_prefix(self):
        self.assertEqual(_strip_recommendation_prefix("⚠ Warning message"), "Warning message")
        self.assertEqual(_strip_recommendation_prefix("🎣 Phishing attempt"), "Phishing attempt")
        self.assertEqual(_strip_recommendation_prefix("Plain recommendation"), "Plain recommendation")

    def test_determine_recommendation_color(self):
        self.assertEqual(_determine_recommendation_color("CRITICAL SECURITY ALERT DEEPFAKE"), Colors.RED)
        self.assertEqual(_determine_recommendation_color("WARNING: CHECK CAREFULLY"), Colors.YELLOW)
        self.assertEqual(_determine_recommendation_color("ROUTINE INSPECTION"), Colors.GREEN)

    def test_print_wrapped_lines_empty(self):
        out = StringIO()
        with patch("sys.stdout", out):
            _print_wrapped_lines([], "►", Colors.RED, Colors.RED)
        self.assertEqual(out.getvalue(), "")

    def test_print_wrapped_lines_multi(self):
        out = StringIO()
        with patch("sys.stdout", out):
            _print_wrapped_lines(["Line 1", "Line 2"], "►", Colors.RED, Colors.RED)
        output = out.getvalue()
        self.assertIn("Line 1", output)
        self.assertIn("Line 2", output)

    def test_print_recommendations_empty_and_list(self):
        out_empty = StringIO()
        with patch("sys.stdout", out_empty):
            print_recommendations([], width=80, risk_color=Colors.GREEN)
        self.assertIn("No specific actions required", out_empty.getvalue())

        out_list = StringIO()
        with patch("sys.stdout", out_list):
            print_recommendations(
                ["🎣 Do not click any links in this email", "⚠ Verify sender phone number"],
                width=80,
                risk_color=Colors.RED,
            )
        output = out_list.getvalue()
        self.assertIn("RECOMMENDATIONS", output)
        self.assertIn("Do not click any links in this email", output)
        self.assertIn("Verify sender phone number", output)


class TestRenderAlertAndCleanReport(unittest.TestCase):
    """Tests for full render_alert and render_clean_report workflows."""

    def test_render_alert_valid_and_invalid_timestamp(self):
        report_valid = _make_report(timestamp="2026-03-30T14:30:00")
        out1 = StringIO()
        with patch("sys.stdout", out1):
            render_alert(report_valid, {})
        self.assertIn("Mar 30, 2026 at 14:30:00", out1.getvalue())

        report_invalid = _make_report(timestamp="invalid-timestamp")
        out2 = StringIO()
        with patch("sys.stdout", out2):
            render_alert(report_invalid, {})
        self.assertIn("invalid-timestamp", out2.getvalue())

    def test_render_clean_report_full_formatting(self):
        report = _make_report(
            overall_threat_score=12.5,
            timestamp="2026-03-30T10:15:30",
            sender="alice@example.org",
            subject="Team Sync Notes",
        )
        out = StringIO()
        with patch("sys.stdout", out):
            render_clean_report(report, threat_low=30.0, terminal_width=120)
        output = out.getvalue()
        self.assertIn("CLEAN", output)
        self.assertIn("10:15:30", output)
        self.assertIn("Score: 12.5", output)
        self.assertIn("alice@example.org", output)
        self.assertIn("Team Sync Notes", output)

    def test_render_clean_report_invalid_timestamp_and_empty_subject(self):
        report = _make_report(
            overall_threat_score=0.0,
            timestamp="bad-time",
            sender="carol@test.com",
            subject="",
        )
        out = StringIO()
        with patch("sys.stdout", out):
            render_clean_report(report, threat_low=0.0, terminal_width=80)
        output = out.getvalue()
        self.assertIn("bad-time", output)
        self.assertIn("(No Subject)", output)

    def test_render_clean_report_yellow_threshold(self):
        report = _make_report(
            overall_threat_score=25.0,  # 25 / 30 > 0.6 -> yellow bar
            timestamp="2026-03-30T10:00:00",
            sender="dave@test.com",
            subject="Check this",
        )
        out = StringIO()
        with patch("sys.stdout", out):
            render_clean_report(report, threat_low=30.0, terminal_width=80)
        self.assertIn("Score: 25.0", out.getvalue())


if __name__ == "__main__":
    unittest.main()
