"""
Console alert rendering helpers.

Builds the terminal card output for threat alerts and clean email reports.
"""

import shutil
import textwrap
from datetime import datetime
from typing import Dict, List

from ..utils.colors import Colors
from ..utils.sanitization import ANSI_ESCAPE_PATTERN
from .alert_channels import (
    REDACTED_URL_PATTERN,
    sanitize_text,
    redact_sensitive_url_params,
)
from .alert_recommendations import (
    RECOMMENDATION_PREFIXES,
    RECOMMENDATION_PREFIXES_TUPLE,
    RED_KEYWORDS_PATTERN,
    YELLOW_KEYWORDS_PATTERN,
)
from .alert_report import RenderConfig, ThreatReport


def get_terminal_width() -> int:
    """Get the current terminal width or default to 80.

    This is wrapped in a try/except so we don't crash in environments where
    shutil.get_terminal_size is unavailable or cannot determine the size.
    In those cases we conservatively fall back to 80 columns.
    """
    try:
        return shutil.get_terminal_size((80, 20)).columns
    except (AttributeError, OSError, ValueError):
        # AttributeError: get_terminal_size might not exist (older/embedded runtimes)
        # OSError/ValueError: terminal size can't be determined in this environment
        return 80


def get_visual_length(text: str) -> int:
    """Get the character count of text after stripping ANSI color codes."""
    if not text:
        return 0
    if "\x1b" in text:
        return len(ANSI_ESCAPE_PATTERN.sub("", text))
    return len(text)


def truncate_text(text: str, width: int) -> str:
    """
    Truncate text to a specified width based on character count.
    Adds '...' if truncated. Assumes input text has no ANSI codes.
    """
    if not text:
        return ""

    # Simple truncation since input (sanitized sender/subject) doesn't have ANSI codes
    if len(text) > width:
        # We need at least 3 chars for '...'
        if width <= 3:
            return "." * width
        return text[: width - 3] + "..."
    return text


def safe_console_url(url: str) -> str:
    """Return a URL safe for console output with tokens redacted."""
    redacted_url = REDACTED_URL_PATTERN.sub(
        "[REDACTED]", redact_sensitive_url_params(url)
    )
    return sanitize_text(redacted_url, csv_safe=True)


def print_alert_row(text: str, risk_color: str, indent: int = 0):
    """Helper to print a row with the left border."""
    # Note: We don't print the right border '│' because calculating visual width
    # with ANSI codes and unicode/emojis is complex without external dependencies.
    # The design uses an open-sided card metaphor for text rows.
    prefix = Colors.colorize("│", risk_color) + " " * (2 + indent)
    print(f"{prefix}{text}")


def print_alert_header(
    risk_level: str,
    render_config: RenderConfig,
):
    """Print the alert header."""
    print()
    # Top Border (┌───┐)
    # Width adjustment: -2 for the corners
    border_len = render_config.width - 2
    print(Colors.colorize(f"┌{'─'*border_len}┐", render_config.risk_color))

    # Header Row
    title = "🚨 SECURITY ALERT"
    risk_label = f"{risk_level.upper()} RISK"

    # Padding calculation:
    # Width - (left_border + space) - title_len - padding - risk_label_len - (space + symbol + right_border)
    # Visual estimation:
    # │  (3 chars visual)
    # title (~18 chars visual with emoji)
    # risk_label (variable)
    # symbol (1-2 chars visual)
    # right_border (not printed in header row in original, but let's add it if we can align)

    # Simpler approach for header: Just use the same layout but maybe without the right border for the text row
    # strictly if alignment is hard. But the PR comment asked for closed borders.
    # Let's try to close the top/bottom/separators first as requested.

    # Padding for the header text row:
    # We need to fill the space between title and risk label.
    # Fixed width = render_config.width
    # Content = "│  " + title + PADDING + risk_label + " " + symbol
    # We don't print a right border '│' here because alignment is tricky with emojis.
    # But we can try to approximate.

    # Magic number explanation:
    # 5 comes from: 3 chars for left prefix ("│  ") + 1 char space before symbol + 1 char approx for symbol/emoji width variance
    padding_len = render_config.width - len(title) - len(risk_label) - 5
    padding = " " * max(1, padding_len)

    print(
        Colors.colorize("│  ", render_config.risk_color)
        + Colors.colorize(title, Colors.BOLD)
        + padding
        + Colors.colorize(risk_label, render_config.risk_color + Colors.BOLD)
        + " "
        + render_config.risk_symbol
    )

    # Separator (├───┤)
    print(Colors.colorize(f"├{'─'*border_len}┤", render_config.risk_color))


def print_alert_metadata(
    report: ThreatReport, width: int, risk_color: str, formatted_time: str
):
    """Print alert metadata (Timestamp, Subject, From, To)."""
    max_field_len = width - 15

    def safe_field(val):
        s = sanitize_text(val, csv_safe=True)
        if len(s) > max_field_len:
            return s[: max_field_len - 3] + "..."
        return s

    print_alert_row(
        f"{Colors.colorize('Timestamp:', Colors.BOLD)} {formatted_time}", risk_color
    )
    print_alert_row(
        f"{Colors.colorize('Subject:', Colors.BOLD)}   {safe_field(report.subject)}",
        risk_color,
    )
    print_alert_row(
        f"{Colors.colorize('From:', Colors.BOLD)}      {safe_field(report.sender)}",
        risk_color,
    )
    print_alert_row(
        f"{Colors.colorize('To:', Colors.BOLD)}        {safe_field(report.recipient)}",
        risk_color,
    )
    print_alert_row("", risk_color)


def print_threat_score(
    score: float, risk_level: str, width: int, risk_color: str
):
    """Print the threat score and progress bar."""
    score_val = min(max(score, 0), 100)
    meter_len = 40
    filled_len = int(score_val / 100 * meter_len)
    bar = "█" * filled_len + "░" * (meter_len - filled_len)
    meter_color = Colors.get_risk_color(risk_level)

    print_alert_row(
        f"{Colors.colorize('THREAT SCORE:', Colors.BOLD)} {score:.2f}/100",
        risk_color,
    )
    print_alert_row(f"{Colors.colorize(bar, meter_color)}", risk_color)


def print_analysis_section_header(
    title: str, analysis_data: Dict, risk_color: str
) -> None:
    level = analysis_data.get("risk_level", "unknown")
    color = Colors.get_risk_color(level)
    symbol = Colors.get_risk_symbol(level)
    print_alert_row(
        f"{Colors.colorize(title + ':', Colors.BOLD)} {Colors.colorize(level.upper(), color)} {symbol}",
        risk_color,
    )


def print_nlp_details(nlp_analysis: Dict, risk_color: str, max_nlp: int) -> None:
    has_nlp = False

    indicator_configs = [
        ("social_engineering_indicators", "Social Engineering:", Colors.RED),
        ("urgency_markers", "Urgency Markers:", Colors.YELLOW),
        ("authority_impersonation", "Authority Impersonation:", Colors.RED),
        ("psychological_triggers", "Psychological Triggers:", Colors.YELLOW),
    ]

    for key, title, item_color in indicator_configs:
        items = nlp_analysis.get(key)
        if items:
            print_alert_row(
                Colors.colorize(title, Colors.BOLD), risk_color, indent=3
            )
            for item in items[:max_nlp]:
                print_alert_row(
                    f"{Colors.colorize('•', item_color)} {item}",
                    risk_color,
                    indent=5,
                )
            has_nlp = True

    if not has_nlp:
        print_alert_row(
            f"{Colors.colorize('✓', Colors.GREEN)} No NLP threats detected",
            risk_color,
            indent=3,
        )


def print_media_details(media_analysis: Dict, risk_color: str, max_media: int) -> None:
    has_media_warnings = False

    indicator_configs = [
        ("file_type_warnings", "File Warnings:", Colors.YELLOW),
        ("suspicious_attachments", "Suspicious Attachments:", Colors.RED),
        ("size_anomalies", "Size Anomalies:", Colors.YELLOW),
        ("potential_deepfakes", "Potential Deepfakes:", Colors.RED),
    ]

    for key, title, item_color in indicator_configs:
        items = media_analysis.get(key)
        if items:
            print_alert_row(
                Colors.colorize(title, Colors.BOLD), risk_color, indent=3
            )
            for item in items[:max_media]:
                print_alert_row(
                    f"{Colors.colorize('•', item_color)} {item}",
                    risk_color,
                    indent=5,
                )
            has_media_warnings = True

    if not has_media_warnings:
        print_alert_row(
            f"{Colors.colorize('✓', Colors.GREEN)} Attachments appear safe",
            risk_color,
            indent=3,
        )


def spam_indicator_rows(indicators: List[str], max_spam: int) -> List[tuple[str, int]]:
    return [
        (f"{Colors.colorize('•', Colors.GREY)} {indicator}", 3)
        for indicator in indicators[:max_spam]
    ]


def spam_header_issue_rows(
    header_issues: List[str], max_header: int
) -> List[tuple[str, int]]:
    rows: List[tuple[str, int]] = []
    if header_issues:
        rows.append((Colors.colorize("Header Issues:", Colors.BOLD), 3))
    rows.extend(
        (f"{Colors.colorize('•', Colors.YELLOW)} {issue}", 5)
        for issue in header_issues[:max_header]
    )
    return rows


def spam_url_rows(suspicious_urls: List[str], max_urls: int) -> List[tuple[str, int]]:
    rows: List[tuple[str, int]] = []
    if suspicious_urls:
        rows.append((Colors.colorize("Suspicious URLs:", Colors.BOLD), 3))
    rows.extend(
        (f"{Colors.colorize('•', Colors.RED)} {safe_console_url(url)}", 5)
        for url in suspicious_urls[:max_urls]
    )
    return rows


def spam_detail_rows(
    spam_analysis: Dict,
    max_spam: int,
    max_header: int,
    max_urls: int,
) -> List[tuple[str, int]]:
    rows: List[tuple[str, int]] = []
    rows.extend(spam_indicator_rows(spam_analysis.get("indicators") or [], max_spam))
    rows.extend(spam_header_issue_rows(spam_analysis.get("header_issues") or [], max_header))
    rows.extend(spam_url_rows(spam_analysis.get("suspicious_urls") or [], max_urls))
    return rows


def print_spam_details(
    spam_analysis: Dict,
    risk_color: str,
    limits: Dict[str, int],
) -> None:
    max_spam = limits.get("MAX_SPAM_INDICATORS_DISPLAY", 5)
    max_header = limits.get("MAX_HEADER_ISSUES_DISPLAY", 5)
    max_urls = limits.get("MAX_URLS_DISPLAY", 3)
    rows = spam_detail_rows(spam_analysis, max_spam, max_header, max_urls)
    if not rows:
        print_alert_row(
            f"{Colors.colorize('✓', Colors.GREEN)} No suspicious patterns",
            risk_color,
            indent=3,
        )
        return

    for text, indent in rows:
        print_alert_row(text, risk_color, indent=indent)


def print_analysis_details(
    report: ThreatReport,
    width: int,
    risk_color: str,
    limits: Dict[str, int],
):
    """Print detailed analysis sections."""
    border_len = width - 2
    print(Colors.colorize(f"├{'─'*border_len}┤", risk_color))
    print_alert_row(
        Colors.colorize("ANALYSIS DETAILS", Colors.BOLD), risk_color
    )
    print_alert_row("", risk_color)

    # Spam
    print_analysis_section_header("📧 SPAM", report.spam_analysis, risk_color)
    print_spam_details(
        report.spam_analysis,
        risk_color,
        limits,
    )
    print_alert_row("", risk_color)

    # NLP
    print_analysis_section_header("🧠 NLP", report.nlp_analysis, risk_color)
    print_nlp_details(
        report.nlp_analysis,
        risk_color,
        limits.get("MAX_NLP_INDICATORS_DISPLAY", 3),
    )
    print_alert_row("", risk_color)

    # Media
    print_analysis_section_header(
        "📎 MEDIA", report.media_analysis, risk_color
    )
    print_media_details(
        report.media_analysis,
        risk_color,
        limits.get("MAX_MEDIA_WARNINGS_DISPLAY", 3),
    )


def _strip_recommendation_prefix(rec: str) -> str:
    """Remove existing prefixes to prevent double icons."""
    while rec.startswith(RECOMMENDATION_PREFIXES_TUPLE):
        for prefix in RECOMMENDATION_PREFIXES:
            if rec.startswith(prefix):
                rec = rec[len(prefix) :]
                break
    return rec


def _determine_recommendation_color(rec_upper: str) -> str:
    """Determine the recommendation color based on keywords."""
    if RED_KEYWORDS_PATTERN.search(rec_upper):
        return Colors.RED
    if YELLOW_KEYWORDS_PATTERN.search(rec_upper):
        return Colors.YELLOW
    return Colors.GREEN


def _print_wrapped_lines(wrapped_lines: List[str], icon: str, color: str, risk_color: str) -> None:
    """Print wrapped recommendation lines with appropriate formatting."""
    if not wrapped_lines:
        return

    # First line gets the bullet point
    first_line = wrapped_lines[0]
    print_alert_row(
        f"{Colors.colorize(icon, color)} {first_line}", risk_color
    )

    # Subsequent lines get indentation based on icon width
    indent = "   " if icon == "⚠️ " else "  "

    for line in wrapped_lines[1:]:
        print_alert_row(f"{indent}{line}", risk_color)


def print_recommendations(
    recommendations: List[str], width: int, risk_color: str
):
    """Print recommendations section."""
    border_len = width - 2
    print(Colors.colorize(f"├{'─'*border_len}┤", risk_color))
    print_alert_row(
        Colors.colorize("RECOMMENDATIONS", Colors.BOLD), risk_color
    )
    print_alert_row("", risk_color)

    for rec in recommendations:
        # Compute uppercase before stripping prefixes so keyword matching matches
        # the original implementation.
        rec_upper = rec.upper()
        rec = _strip_recommendation_prefix(rec)
        color = _determine_recommendation_color(rec_upper)
        icon = "►"

        # Calculate available width for text
        max_text_width = width - 8

        # Wrap text nicely
        wrapped_lines = textwrap.wrap(rec, width=max_text_width)
        _print_wrapped_lines(wrapped_lines, icon, color, risk_color)

    # Bottom Border (└───┘)
    print(Colors.colorize(f"└{'─'*border_len}┘", risk_color))
    print()


def render_alert(report: ThreatReport, limits: Dict[str, int]) -> None:
    """Render the full console alert card for a threat report."""
    # Configuration
    width = 70
    risk_color = Colors.get_risk_color(report.risk_level)
    risk_symbol = Colors.get_risk_symbol(report.risk_level)

    # Format timestamp
    try:
        dt = datetime.fromisoformat(report.timestamp)
        formatted_time = dt.strftime("%b %d, %Y at %H:%M:%S")
    except ValueError:
        formatted_time = report.timestamp

    render_config = RenderConfig(
        width=width,
        risk_color=risk_color,
        risk_symbol=risk_symbol,
    )

    print_alert_header(report.risk_level, render_config)
    print_alert_metadata(report, width, risk_color, formatted_time)
    print_threat_score(
        report.overall_threat_score, report.risk_level, width, risk_color
    )
    print_analysis_details(report, width, risk_color, limits)
    print_recommendations(report.recommendations, width, risk_color)


def render_clean_report(report: ThreatReport, threat_low: float, terminal_width: int) -> None:
    """Render the compact one-line clean report."""
    # Compact format for clean emails
    score_val = max(0.0, report.overall_threat_score)

    # Calculate risk relative to the low threshold (the "clean" budget)
    threshold = threat_low
    if threshold <= 0:
        threshold = 30

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

    # Determine available width based on terminal size
    # Calculate width of fixed parts dynamically
    # Structure: "✓ CLEAN | HH:MM:SS | Score: XX.X [■■···] | From: " + sender + " | " + subject

    sep = Colors.colorize("│", Colors.GREY)

    clean_str = Colors.colorize("✓ CLEAN", Colors.GREEN)
    prefix = f"{clean_str} {sep} {time_str} {sep} Score: {score_val:4.1f} {visual_bar} {sep} From: "
    prefix_len = get_visual_length(prefix)

    suffix_sep = f" {sep} "
    suffix_sep_len = get_visual_length(suffix_sep)

    # Fixed width is prefix + space for suffix separator
    # We add 1 char buffer
    fixed_width = prefix_len + suffix_sep_len + 1

    available_width = max(20, terminal_width - fixed_width)

    # Allocate width: 35% for sender, 65% for subject
    sender_target = int(available_width * 0.35)
    # Minimum reduced to 8 to fit 80-column terminals better
    sender_width = max(8, sender_target)

    subject_width = available_width - sender_width
    # Ensure subject has at least some space
    subject_width = max(10, subject_width)

    # Sender truncated
    sanitized_sender = sanitize_text(report.sender, csv_safe=True)
    sender = truncate_text(sanitized_sender, sender_width)

    # Subject truncated
    sanitized_subject = sanitize_text(report.subject, csv_safe=True)
    if not sanitized_subject:
        sanitized_subject = "(No Subject)"

    subject = truncate_text(sanitized_subject, subject_width)

    # Format:
    # ✓ CLEAN | HH:MM:SS | Score: XX.X [■■···] | From: Sender                       | Subject
    print(
        f"{clean_str} "
        f"{sep} {time_str} "
        f"{sep} Score: {score_val:4.1f} {visual_bar} "
        f"{sep} From: {sender:<{sender_width}} "
        f"{sep} {subject}"
    )
