"""
Unit tests for alert channel helpers (src/modules/alert_channels.py).

Covers:
- sanitize_text (clean printable strings, ANSI escapes, control chars, CSV formulas)
- sanitize_for_slack (Slack escaping, control chars, CSV pass-through)
- sanitize_url_for_display (redaction and %5bREDACTED%5d decoding)
- sanitize_error_message (URL extraction, punctuation trimming, error fallback)
- redact_url_secrets, _redact_authority_credentials, _redact_webhook_by_platform
- redact_sensitive_url_params (sensitive query keys, preserve clean params, error handling)
- create_slack_field, _get_analysis_indicator, generate_slack_fields
- build_webhook_payload, build_slack_payload
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.alert_channels import (
    _get_analysis_indicator,
    _redact_authority_credentials,
    _redact_discord_webhook,
    _redact_slack_webhook,
    _redact_webhook_by_platform,
    _sanitize_unprintable,
    build_slack_payload,
    build_webhook_payload,
    create_slack_field,
    generate_slack_fields,
    redact_sensitive_url_params,
    redact_url_secrets,
    sanitize_error_message,
    sanitize_for_slack,
    sanitize_text,
    sanitize_url_for_display,
)
from src.modules.alert_report import ThreatReport


def _create_sample_report(**kwargs) -> ThreatReport:
    """Helper to create a populated ThreatReport."""
    defaults = {
        "email_id": "test-msg-001",
        "subject": "Urgent: Verify Account Details",
        "sender": "Security Team <security@example.com>",
        "recipient": "user@example.com",
        "date": "2025-01-01T12:00:00Z",
        "overall_threat_score": 85.5,
        "risk_level": "high",
        "spam_analysis": {
            "score": 80.0,
            "risk_level": "high",
            "indicators": ["spam_phrase"],
            "suspicious_urls": [
                "https://phishing.site/login?token=abc12345",
                "https://normal.site/home",
            ],
        },
        "nlp_analysis": {
            "score": 90.0,
            "risk_level": "high",
            "social_engineering_indicators": ["urgency_pressure"],
            "authority_impersonation": "CEO",
        },
        "media_analysis": {
            "score": 85.0,
            "risk_level": "high",
            "file_type_warnings": ["executable_attachment"],
            "potential_deepfakes": ["video_face_swap"],
        },
        "recommendations": ["Do not click links", "Report to SOC"],
        "timestamp": "2025-01-01T12:00:05Z",
    }
    defaults.update(kwargs)
    return ThreatReport(**defaults)


class TestSanitizeText(unittest.TestCase):
    """Tests for sanitize_text and _sanitize_unprintable."""

    def test_empty_or_none_string(self):
        self.assertEqual(sanitize_text(""), "")
        self.assertEqual(sanitize_text(None), "")

    def test_printable_ascii_fast_path(self):
        text = "Hello, World! 123 @#$"
        self.assertEqual(sanitize_text(text), text)

    def test_control_characters_and_whitespace_normalization(self):
        # Tabs and newlines should become spaces; bell and other control chars removed
        raw = "Line 1\nLine 2\tWith\x07Bell"
        sanitized = sanitize_text(raw)
        self.assertNotIn("\n", sanitized)
        self.assertNotIn("\t", sanitized)
        self.assertNotIn("\x07", sanitized)
        self.assertEqual(sanitized, "Line 1 Line 2 WithBell")

    def test_ansi_escape_code_removal(self):
        raw = "\x1b[31;1mDangerous Red Text\x1b[0m"
        self.assertEqual(sanitize_text(raw), "Dangerous Red Text")

    def test_bidi_override_removal(self):
        # RTL override \u202e
        raw = "Safe\u202eReversed"
        self.assertEqual(sanitize_text(raw), "SafeReversed")

    def test_csv_safe_flag(self):
        formula = "=SUM(1, 2)"
        self.assertEqual(sanitize_text(formula, csv_safe=False), "=SUM(1, 2)")
        self.assertEqual(sanitize_text(formula, csv_safe=True), "'=SUM(1, 2)")

    def test_sanitize_unprintable_direct(self):
        raw = "\x1b[32m\tClean\x08Text\n\x1b[0m"
        result = _sanitize_unprintable(raw)
        self.assertEqual(result, " CleanText ")


class TestSanitizeForSlack(unittest.TestCase):
    """Tests for sanitize_for_slack."""

    def test_empty_string(self):
        self.assertEqual(sanitize_for_slack(""), "")
        self.assertEqual(sanitize_for_slack(None), "")

    def test_slack_special_character_escaping(self):
        raw = "Tom & Jerry <tom@example.com> > Out"
        expected = "Tom &amp; Jerry &lt;tom@example.com&gt; &gt; Out"
        self.assertEqual(sanitize_for_slack(raw), expected)

    def test_does_not_csv_prefix_formulas(self):
        # Slack messages shouldn't get prefixed with single quotes for CSV formula prevention
        raw = "=CMD('calc')"
        self.assertEqual(sanitize_for_slack(raw), "=CMD('calc')")

    def test_control_character_removal_with_slack_escaping(self):
        raw = "\x1b[31m<script>&test</script>\x1b[0m"
        expected = "&lt;script&gt;&amp;test&lt;/script&gt;"
        self.assertEqual(sanitize_for_slack(raw), expected)


class TestRedactUrlSecrets(unittest.TestCase):
    """Tests for URL secret redaction and credential handling."""

    def test_empty_url(self):
        self.assertEqual(redact_url_secrets(""), "")
        self.assertEqual(redact_url_secrets(None), "")

    def test_authority_credentials_with_username_and_password(self):
        url = "https://admin:mysecret123@internal.corp.com:8443/api"
        expected = "https://admin:[REDACTED]@internal.corp.com:8443/api"
        self.assertEqual(redact_url_secrets(url), expected)

    def test_authority_credentials_with_password_only(self):
        url = "https://:mysecret123@internal.corp.com/api"
        expected = "https://:[REDACTED]@internal.corp.com/api"
        self.assertEqual(redact_url_secrets(url), expected)

    def test_authority_without_password(self):
        parsed = urlparse("https://user@internal.corp.com/api")
        result = _redact_authority_credentials(parsed)
        self.assertEqual(result.netloc, "user@internal.corp.com")

    def test_slack_webhook_redaction(self):
        url = "https://hooks.slack.com/services/T0001/B0002/SECRET_TOKEN_XYZ"
        expected = "https://hooks.slack.com/services/T0001/B0002/[REDACTED]"
        self.assertEqual(redact_url_secrets(url), expected)

    def test_slack_webhook_short_path_ignored(self):
        parsed = urlparse("https://hooks.slack.com/services/T0001")
        self.assertIsNone(_redact_slack_webhook(parsed))

    def test_discord_webhook_redaction(self):
        url = "https://discord.com/api/webhooks/1234567890/WEBHOOK_TOKEN_XYZ"
        expected = "https://discord.com/api/webhooks/1234567890/[REDACTED]"
        self.assertEqual(redact_url_secrets(url), expected)

    def test_discord_webhook_subdomain(self):
        url = "https://ptb.discord.com/api/webhooks/1234567890/WEBHOOK_TOKEN_XYZ"
        expected = "https://ptb.discord.com/api/webhooks/1234567890/[REDACTED]"
        self.assertEqual(redact_url_secrets(url), expected)

    def test_discord_webhook_helper_direct(self):
        parsed = urlparse("https://discord.com/api/webhooks/123/TOKEN")
        res = _redact_discord_webhook(parsed)
        self.assertIsNotNone(res)
        self.assertTrue(res.path.endswith("[REDACTED]"))

    def test_redact_webhook_by_platform_not_matching(self):
        parsed = urlparse("https://otherdomain.com/services/T1/B2/token")
        self.assertIsNone(
            _redact_webhook_by_platform(parsed, "/services/", "slack.com")
        )

    def test_url_with_sensitive_query_parameters(self):
        url = "https://example.com/callback?code=xyz&token=secret123&state=ok"
        redacted = redact_url_secrets(url)
        self.assertIn("token=%5BREDACTED%5D", redacted)
        self.assertIn("code=xyz", redacted)
        self.assertIn("state=ok", redacted)

    def test_clean_url_fast_path(self):
        url = "https://example.com/path/to/page"
        self.assertEqual(redact_url_secrets(url), url)

    def test_malformed_url_exception_fallback(self):
        with patch(
            "src.modules.alert_channels.urlparse", side_effect=ValueError("bad url")
        ):
            self.assertEqual(
                redact_url_secrets("https://invalid-url"), "https://invalid-url"
            )


class TestRedactSensitiveUrlParams(unittest.TestCase):
    """Tests for redact_sensitive_url_params."""

    def test_empty_string(self):
        self.assertEqual(redact_sensitive_url_params(""), "")
        self.assertEqual(redact_sensitive_url_params(None), "")

    def test_sensitive_keys_redacted(self):
        sensitive_keys = [
            "password",
            "token",
            "secret",
            "key",
            "apikey",
            "api_key",
            "access_token",
            "auth",
            "authorization",
            "sig",
            "signature",
        ]
        for key in sensitive_keys:
            url = f"https://example.com/test?{key}=supersecret&param=safe"
            redacted = redact_sensitive_url_params(url)
            self.assertIn(f"{key}=%5BREDACTED%5D", redacted)
            self.assertIn("param=safe", redacted)
            self.assertNotIn("supersecret", redacted)

    def test_case_insensitive_sensitive_keys(self):
        url = "https://example.com/test?API_KEY=val1&TOKEN=val2"
        redacted = redact_sensitive_url_params(url)
        self.assertIn("API_KEY=%5BREDACTED%5D", redacted)
        self.assertIn("TOKEN=%5BREDACTED%5D", redacted)

    def test_multiple_values_for_same_key(self):
        url = "https://example.com/test?token=val1&token=val2"
        redacted = redact_sensitive_url_params(url)
        self.assertIn("token=%5BREDACTED%5D", redacted)
        self.assertNotIn("val1", redacted)
        self.assertNotIn("val2", redacted)

    def test_clean_urls_unchanged(self):
        url = "https://example.com/search?q=security&page=1"
        self.assertEqual(redact_sensitive_url_params(url), url)

    def test_parameter_free_url_fast_path(self):
        url = "https://example.com/about/us"
        self.assertEqual(redact_sensitive_url_params(url), url)

    def test_url_with_empty_query_string(self):
        url = "https://example.com/test?"
        self.assertEqual(redact_sensitive_url_params(url), url)

    def test_exception_fallback(self):
        with patch(
            "src.modules.alert_channels.parse_qs", side_effect=Exception("parsing fail")
        ):
            self.assertEqual(
                redact_sensitive_url_params("https://example.com?token=123"),
                "https://example.com?token=123",
            )


class TestSanitizeUrlForDisplay(unittest.TestCase):
    """Tests for sanitize_url_for_display."""

    def test_replaces_percent_encoded_redacted_tokens(self):
        url = "https://example.com/test?token=secret123&key=xyz"
        displayed = sanitize_url_for_display(url)
        self.assertIn("token=[REDACTED]", displayed)
        self.assertIn("key=[REDACTED]", displayed)
        self.assertNotIn("%5BREDACTED%5D", displayed)
        self.assertNotIn("%5bREDACTED%5d", displayed)


class TestSanitizeErrorMessage(unittest.TestCase):
    """Tests for sanitize_error_message."""

    def test_redacts_http_and_https_urls(self):
        err = (
            "Request failed for https://api.slack.com/services/T1/B2/SECRET_TOKEN: 404"
        )
        result = sanitize_error_message(err)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("SECRET_TOKEN", result)

    def test_redacts_query_parameters_in_error(self):
        err = "Failed connection to https://service.local/auth?api_key=secretkey123"
        result = sanitize_error_message(err)
        self.assertIn("%5BREDACTED%5D", result)
        self.assertNotIn("secretkey123", result)

    def test_strips_trailing_punctuation(self):
        err = "See https://example.com/login?token=abc12345.,;:)'"
        result = sanitize_error_message(err)
        self.assertIn("token=%5BREDACTED%5D", result)
        self.assertNotIn("abc12345", result)

    def test_multiple_urls_in_error(self):
        err = (
            "Webhook 1 https://hooks.slack.com/services/T1/B1/TOK1 failed; "
            "Webhook 2 https://discord.com/api/webhooks/999/TOK2 failed"
        )
        result = sanitize_error_message(err)
        self.assertNotIn("TOK1", result)
        self.assertNotIn("TOK2", result)
        self.assertEqual(result.count("[REDACTED]"), 2)

    def test_error_without_urls_unchanged(self):
        err = "Timeout connecting to host"
        self.assertEqual(sanitize_error_message(err), "Timeout connecting to host")

    def test_exception_fallback(self):
        with patch(
            "src.modules.alert_channels.redact_url_secrets",
            side_effect=Exception("redaction error"),
        ):
            self.assertEqual(
                sanitize_error_message("https://example.com"),
                "An error occurred (details redacted for security)",
            )


class TestSlackFieldsAndPayload(unittest.TestCase):
    """Tests for Slack field formatting and Slack / webhook payload generation."""

    def test_create_slack_field(self):
        field = create_slack_field(
            "Spam Analysis", {"risk_level": "high", "score": 85.0}, " - Suspicious URLs"
        )
        self.assertEqual(field["title"], "Spam Analysis")
        self.assertIn("HIGH (85.00)", field["value"])
        self.assertIn("- Suspicious URLs", field["value"])
        self.assertTrue(field["short"])

    def test_create_slack_field_unknown_level(self):
        field = create_slack_field("Test", {}, "")
        self.assertIn("UNKNOWN (0.00)", field["value"])

    def test_get_analysis_indicator_with_defaults(self):
        data = {"suspicious_urls": ["http://phish.com"]}
        indicator = _get_analysis_indicator(
            data,
            ["indicators", "suspicious_urls"],
            {"suspicious_urls": "Suspicious URLs"},
        )
        self.assertEqual(indicator, " - Suspicious URLs")

    def test_get_analysis_indicator_with_list_value(self):
        data = {"indicators": ["phishing_trigger_phrase", "urgency"]}
        indicator = _get_analysis_indicator(data, ["indicators"], {})
        self.assertEqual(indicator, " - phishing_trigger_phrase")

    def test_get_analysis_indicator_empty(self):
        self.assertEqual(_get_analysis_indicator({}, ["key1"], {}), "")

    def test_generate_slack_fields(self):
        report = _create_sample_report()
        fields = generate_slack_fields(report)
        titles = [f["title"] for f in fields]
        self.assertIn("Subject", titles)
        self.assertIn("From", titles)
        self.assertIn("Overall Threat Score", titles)
        self.assertIn("📧 Spam Analysis", titles)
        self.assertIn("🧠 NLP Analysis", titles)
        self.assertIn("📎 Media Analysis", titles)
        self.assertIn("Top Recommendation", titles)

    def test_generate_slack_fields_empty_recommendations(self):
        report = _create_sample_report(recommendations=[])
        fields = generate_slack_fields(report)
        rec_field = next(f for f in fields if f["title"] == "Top Recommendation")
        self.assertEqual(rec_field["value"], "Review email")

    def test_build_slack_payload_colors(self):
        for risk, expected_color in [
            ("low", "#36a64f"),
            ("medium", "#ff9900"),
            ("high", "#ff0000"),
            ("unknown", "#808080"),
        ]:
            report = _create_sample_report(risk_level=risk)
            payload = build_slack_payload(report)
            self.assertEqual(payload["attachments"][0]["color"], expected_color)
            self.assertIn(
                f"🚨 Security Alert - {risk.upper()} Risk",
                payload["attachments"][0]["title"],
            )
            self.assertEqual(payload["text"], "New email security threat detected")

    def test_build_webhook_payload_redacts_suspicious_urls(self):
        report = _create_sample_report()
        payload = build_webhook_payload(report)
        suspicious_urls = payload["spam_analysis"]["suspicious_urls"]
        self.assertIn("token=%5BREDACTED%5D", suspicious_urls[0])
        self.assertNotIn("abc12345", suspicious_urls[0])
        self.assertEqual(suspicious_urls[1], "https://normal.site/home")

    def test_build_webhook_payload_without_spam_analysis(self):
        report = _create_sample_report(spam_analysis={})
        payload = build_webhook_payload(report)
        self.assertEqual(payload["spam_analysis"], {})


if __name__ == "__main__":
    unittest.main()
