"""
Alert channel helpers.

Handles payload construction, text/URL sanitization, and token redaction for
webhook and Slack alerting. HTTP calls remain in the alert facade.
"""

import re
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..utils.colors import Colors
from ..utils.sanitization import (
    _TRANSLATOR,
    _WHITESPACE_TRANS,
    ANSI_ESCAPE_PATTERN,
    sanitize_for_csv,
)
from .alert_report import ThreatReport


# Regex pattern for extracting URLs from error messages (compiled once for performance)
# Expanded to catch bare paths/hosts for complete redaction when scheme is missing.
URL_PATTERN = re.compile(r'(?:https?://[^\s<>"]+|www\.[^\s<>"]+|/[^\s<>"]+)')

# Pre-compiled pattern for fast URL redaction replacement without re.IGNORECASE penalty
REDACTED_URL_PATTERN = re.compile(r"%5[bB]REDACTED%5[dD]", flags=0)


def sanitize_text(text: str, csv_safe: bool = False) -> str:
    """
    Sanitize text for safe output.
    Removes control characters, BiDi overrides, and normalizes whitespace.

    Args:
        text: Input text
        csv_safe: If True, applies CSV/Formula injection prevention

    """
    if not text:
        return ""

    # Replace newlines and tabs with spaces
    sanitized = (
        text.translate(_WHITESPACE_TRANS)
        if "\n" in text or "\r" in text or "\t" in text
        else text
    )

    if "\x1b" in sanitized:
        sanitized = ANSI_ESCAPE_PATTERN.sub("", sanitized)

    # Remove non-printable characters (including BiDi overrides, control chars, etc.)
    # Only keep characters that are printable or separators (Zs)
    # Optimization: Use str.translate with a lazy-evaluating dictionary
    # for significantly faster filtering (~15-20x) than a list comprehension inside join().
    sanitized = sanitized.translate(_TRANSLATOR)

    if csv_safe:
        # Prevent Formula/CSV Injection for console logs that might be exported
        sanitized = sanitize_for_csv(sanitized)

    return sanitized


def sanitize_for_slack(text: str) -> str:
    """
    Sanitize text for Slack to prevent injection and spoofing.
    Escapes &, <, > and sanitizes control characters.
    """
    if not text:
        return ""

    # First sanitize control characters using the existing method
    # We do NOT use csv_safe=True here to avoid messing up Slack formatting
    text = sanitize_text(text, csv_safe=False)

    # Escape Slack special characters
    # Reference: https://api.slack.com/reference/surfaces/formatting#escaping
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def sanitize_url_for_display(url: str) -> str:
    """Redact sensitive tokens/parameters from a URL for safe console display."""
    redacted = redact_url_secrets(url)
    return REDACTED_URL_PATTERN.sub("[REDACTED]", redacted)


def sanitize_error_message(error: str) -> str:
    """
    Sanitize exception messages to prevent leaking sensitive URLs/tokens.
    Detects URLs in the error message and redacts them.
    """
    msg = str(error)

    # ⚡ BOLT: Fast-path string check avoids regex engine overhead
    # Most error messages don't contain URLs. Skipping regex search
    # provides ~4x speedup on clean messages.
    if "http" not in msg:
        if "www" not in msg:
            if "/" not in msg:
                return msg

    try:
        # Find all URLs in the message
        # Simple regex for http/https URLs to catch full URLs including query params
        urls = URL_PATTERN.findall(msg)

        for url in urls:
            # Clean up trailing punctuation that might have been matched
            clean_url = url.rstrip(".,;:)'")

            # Apply redaction
            redacted = redact_url_secrets(clean_url)

            # If redaction changed anything, update the message
            if redacted != clean_url:
                msg = msg.replace(clean_url, redacted)

        return msg
    except Exception:
        return "An error occurred (details redacted for security)"


def _redact_authority_credentials(parsed: Any) -> Any:
    """Redact password/credentials in the netloc of a parsed URL."""
    if not parsed.password:
        return parsed
    _, _, host_part = parsed.netloc.rpartition("@")
    if parsed.username:
        user_pass_part = parsed.netloc.rpartition("@")[0]
        username_part = user_pass_part.partition(":")[0]
        new_netloc = f"{username_part}:[REDACTED]@{host_part}"
    else:
        new_netloc = f":[REDACTED]@{host_part}"
    return parsed._replace(netloc=new_netloc)


def _redact_webhook_by_platform(parsed: Any, prefix: str, domain: str) -> Optional[Any]:
    """Helper to redact webhook token for a specific platform."""
    hostname = (parsed.hostname or "").lower()
    is_platform = not hostname or hostname == domain or hostname.endswith(f".{domain}")
    if is_platform and parsed.path.startswith(prefix):
        parts = parsed.path.split("/")
        if len(parts) >= 5:
            parts[-1] = "[REDACTED]"
            new_path = "/".join(parts)
            return parsed._replace(path=new_path)
    return None


def _redact_slack_webhook(parsed: Any) -> Optional[Any]:
    """Redact Slack webhook token if applicable."""
    return _redact_webhook_by_platform(parsed, "/services/", "slack.com")


def _redact_discord_webhook(parsed: Any) -> Optional[Any]:
    """Redact Discord webhook token if applicable."""
    return _redact_webhook_by_platform(parsed, "/api/webhooks/", "discord.com")


def redact_url_secrets(url: str) -> str:
    """
    Redact sensitive information from URL (query params and specific paths).
    Handles Slack/Discord webhooks and sensitive query parameters.
    """
    try:
        if not url:
            return ""

        url = redact_sensitive_url_params(url)
        parsed = urlparse(url)

        parsed = _redact_authority_credentials(parsed)

        slack_parsed = _redact_slack_webhook(parsed)
        if slack_parsed:
            return urlunparse(slack_parsed)

        discord_parsed = _redact_discord_webhook(parsed)
        if discord_parsed:
            return urlunparse(discord_parsed)

        return urlunparse(parsed)
    except Exception:
        return url


def redact_sensitive_url_params(url: str) -> str:
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
        }

        changed = False
        for key in query_params:
            if key.lower() in sensitive_keys:
                query_params[key] = ["[REDACTED]"]
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


def create_slack_field(title: str, analysis_dict: Dict[str, Any], indicator: str) -> Dict[str, Any]:
    """Helper to create a standard Slack field dictionary with risk emojis."""
    level = analysis_dict.get("risk_level", "unknown")
    score = analysis_dict.get("score", 0)
    symbol = Colors.get_risk_symbol(level)

    value = f"{symbol} {level.upper()} ({score:.2f})"
    if indicator:
        value += f"{indicator}"

    return {"title": title, "value": value, "short": True}


def _get_analysis_indicator(data: Dict[str, Any], keys: List[str], defaults: Dict[str, str]) -> str:
    """Extract a descriptive indicator from analysis data."""
    for key in keys:
        val = data.get(key)
        if val:
            # Prefer a generic label when one is configured (e.g. "Suspicious URLs"),
            # otherwise show the first concrete item from the list.
            if key in defaults:
                return f" - {defaults[key]}"
            if isinstance(val, list) and val:
                return f" - {val[0]}"
    return ""


def generate_slack_fields(report: ThreatReport) -> List[Dict[str, Any]]:
    """Generate the fields array for the Slack payload."""
    fields = [
        {
            "title": "Subject",
            "value": sanitize_for_slack(report.subject),
            "short": False,
        },
        {
            "title": "From",
            "value": sanitize_for_slack(report.sender),
            "short": True,
        },
        {
            "title": "Overall Threat Score",
            "value": f"{report.overall_threat_score:.2f}",
            "short": True,
        },
    ]

    # Spam
    spam_data = report.spam_analysis or {}
    spam_ind = _get_analysis_indicator(
        spam_data, ["indicators", "suspicious_urls"], {"suspicious_urls": "Suspicious URLs"}
    )
    fields.append(create_slack_field("📧 Spam Analysis", spam_data, spam_ind))

    # NLP
    nlp_data = report.nlp_analysis or {}
    nlp_ind = _get_analysis_indicator(
        nlp_data, ["social_engineering_indicators", "authority_impersonation"], {}
    )
    fields.append(create_slack_field("🧠 NLP Analysis", nlp_data, nlp_ind))

    # Media
    media_data = report.media_analysis or {}
    media_ind = _get_analysis_indicator(
        media_data, ["file_type_warnings", "potential_deepfakes"], {"potential_deepfakes": "Deepfake Detected"}
    )
    fields.append(create_slack_field("📎 Media Analysis", media_data, media_ind))

    # Top Recommendation
    fields.append(
        {
            "title": "Top Recommendation",
            "value": (
                report.recommendations[0]
                if report.recommendations
                else "Review email"
            ),
            "short": False,
        }
    )
    return fields


def build_webhook_payload(report: ThreatReport) -> Dict[str, Any]:
    """Build the JSON payload for a webhook alert with sensitive URL redaction."""
    payload = asdict(report)

    # Redact sensitive info from suspicious URLs if present
    if (
        "spam_analysis" in payload
        and "suspicious_urls" in payload["spam_analysis"]
    ):
        urls = payload["spam_analysis"]["suspicious_urls"]
        if urls:
            payload["spam_analysis"]["suspicious_urls"] = [
                redact_sensitive_url_params(url) for url in urls
            ]

    return payload


def build_slack_payload(report: ThreatReport) -> Dict[str, Any]:
    """Build the JSON payload for a Slack alert."""
    color = {"low": "#36a64f", "medium": "#ff9900", "high": "#ff0000"}.get(
        report.risk_level, "#808080"
    )

    fields = generate_slack_fields(report)

    attachments = [
        {
            "color": color,
            "title": (f"🚨 Security Alert - {report.risk_level.upper()} Risk"),
            "fields": fields,
            "footer": "Email Security Pipeline",
            "ts": int(datetime.now().timestamp()),
        }
    ]

    return {
        "text": "New email security threat detected",
        "attachments": attachments,
    }
