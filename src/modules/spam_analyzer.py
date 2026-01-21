"""
Layer 1: Spam Detection Analyzer
Traditional spam scoring based on headers, content patterns, and URLs
"""

import re
import logging
from typing import Dict, List, Tuple, Union
from urllib.parse import urlparse
from dataclasses import dataclass

from .email_ingestion import EmailData


@dataclass
class SpamAnalysisResult:
    """Result of spam analysis"""
    score: float
    indicators: List[str]
    suspicious_urls: List[str]
    header_issues: List[str]
    risk_level: str  # low, medium, high


class SpamAnalyzer:
    """Analyzes emails for spam characteristics"""

    # Spam indicator patterns
    SPAM_KEYWORDS = [
        r'\b(viagra|cialis|pharmacy|pills)\b',
        r'\b(winner|congratulations|prize|lottery)\b',
        r'\b(urgent|immediate|action required|act now)\b',
        r'\b(click here|click now|limited time)\b',
        r'\b(free money|make money|earn cash)\b',
        r'\b(nigerian prince|inheritance|beneficiary)\b',
        r'\b(enlarge|enhancement|weight loss)\b',
        r'\b(casino|poker|gambling)\b',
    ]

    # Pre-compiled regex patterns for performance

    # Generate master pattern with named groups for identification
    _parts = []
    _map = {}
    for _i, _p in enumerate(SPAM_KEYWORDS):
        _g = f"spam_kw_{_i}"
        # Wrap pattern in a named group.
        _parts.append(f"(?P<{_g}>{_p})")
        _map[_g] = _p

    MASTER_SPAM_PATTERN = re.compile("|".join(_parts), re.IGNORECASE)
    MASTER_SPAM_MAP = _map

    # Clean up temporary variables
    del _parts, _map, _i, _p, _g

    # Simple combined pattern (no named groups) for fast detection/counting
    COMBINED_SPAM_PATTERN = re.compile('|'.join(SPAM_KEYWORDS), re.IGNORECASE)

    LINK_PATTERN = re.compile(r'https?://', re.IGNORECASE)
    URL_EXTRACTION_PATTERN = re.compile(r'https?://[^\s<>"]+')
    MONEY_PATTERN = re.compile(r'\$\d+|\d+\s*(dollar|usd|euro)', re.IGNORECASE)
    IMG_TAG_PATTERN = re.compile(r'<img\b', re.IGNORECASE)
    # Use bounded quantifiers to prevent ReDoS (Regular Expression Denial of Service)
    HIDDEN_TEXT_PATTERN = re.compile(r'font-size:\s*[0-2]px|color:\s*#fff.{0,100}background.{0,100}#fff', re.IGNORECASE)
    EMAIL_ADDRESS_PATTERN = re.compile(r'[\w\.-]+@[\w\.-]+')
    SENDER_DOMAIN_PATTERN = re.compile(r'[\w\.-]+@([\w\.-]+)', re.IGNORECASE)
    DISPLAY_NAME_PATTERN = re.compile(r'^([^<]+)<', re.IGNORECASE)

    # Suspicious URL patterns
    SUSPICIOUS_URL_PATTERNS = [
        re.compile(r'bit\.ly'),
        re.compile(r'tinyurl'),
        re.compile(r't\.co'),
        re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),  # IP addresses
        re.compile(r'[a-z0-9\-]{30,}'),  # Very long subdomain/path
    ]

    # Pre-compiled combined pattern for performance
    # To join them, we need the pattern strings
    COMBINED_URL_PATTERN = re.compile('|'.join(p.pattern for p in SUSPICIOUS_URL_PATTERNS), re.IGNORECASE)

    # Additional shorteners specific check regex
    SHORTENER_PATTERN = re.compile(r'(bit\.ly|tinyurl|t\.co|goo\.gl)', re.IGNORECASE)

    def __init__(self, config):
        """
        Initialize spam analyzer

        Args:
            config: AnalysisConfig object
        """
        self.config = config
        self.logger = logging.getLogger("SpamAnalyzer")

    def analyze(self, email_data: EmailData) -> SpamAnalysisResult:
        """
        Perform spam analysis on email

        Args:
            email_data: Email to analyze

        Returns:
            SpamAnalysisResult
        """
        score = 0.0
        indicators = []
        suspicious_urls = []
        header_issues = []

        # Analyze subject line
        subject_score, subject_indicators = self._analyze_subject(email_data.subject)
        score += subject_score
        indicators.extend(subject_indicators)

        # Analyze body content
        body_score, body_indicators = self._analyze_body(
            email_data.body_text,
            email_data.body_html
        )
        score += body_score
        indicators.extend(body_indicators)

        # Check for suspicious URLs
        if self.config.spam_check_urls:
            url_score, found_urls = self._check_urls(
                email_data.body_text + email_data.body_html
            )
            score += url_score
            suspicious_urls.extend(found_urls)

        # Analyze headers
        if self.config.spam_check_headers:
            header_score, issues = self._analyze_headers(email_data.headers)
            score += header_score
            header_issues.extend(issues)

        # Check sender reputation
        sender_score, sender_indicators = self._check_sender(
            email_data.sender,
            email_data.headers
        )
        score += sender_score
        indicators.extend(sender_indicators)

        # Determine risk level
        risk_level = self._calculate_risk_level(score)

        self.logger.debug(
            f"Spam analysis complete: score={score:.2f}, risk={risk_level}"
        )

        return SpamAnalysisResult(
            score=score,
            indicators=indicators,
            suspicious_urls=suspicious_urls,
            header_issues=header_issues,
            risk_level=risk_level
        )

    def _analyze_subject(self, subject: str) -> Tuple[float, List[str]]:
        """Analyze subject line for spam indicators"""
        score = 0.0
        indicators = []
        subject_lower = subject.lower()

        # Check for all caps
        if subject.isupper() and len(subject) > 10:
            score += 1.0
            indicators.append("Subject in all caps")

        # Check for excessive punctuation
        if subject.count('!') > 2:
            score += 0.5
            indicators.append("Excessive exclamation marks")

        # Check spam keywords
        # Optimization: Fast check first, then single-pass identification
        if self.COMBINED_SPAM_PATTERN.search(subject_lower):
            found_groups = set()
            for match in self.MASTER_SPAM_PATTERN.finditer(subject_lower):
                group_name = match.lastgroup
                if group_name and group_name in self.MASTER_SPAM_MAP and group_name not in found_groups:
                    found_groups.add(group_name)
                    pattern_str = self.MASTER_SPAM_MAP[group_name]
                    score += 1.5
                    indicators.append(f"Spam keyword in subject: {pattern_str}")

        # Check for numbers indicating money
        if self.MONEY_PATTERN.search(subject_lower):
            score += 0.5
            indicators.append("Money mentioned in subject")

        return score, indicators

    def _analyze_body(self, text_body: str, html_body: str) -> Tuple[float, List[str]]:
        """Analyze email body for spam indicators"""
        score = 0.0
        indicators = []

        # Optimization: Avoid large string concatenation and lowercasing
        # Instead, scan text and html separately with compiled regex

        keyword_matches = 0

        # Check spam keywords in text body
        if text_body:
            keyword_matches += sum(1 for _ in self.COMBINED_SPAM_PATTERN.finditer(text_body))

        # Check spam keywords in html body
        if html_body:
            keyword_matches += sum(1 for _ in self.COMBINED_SPAM_PATTERN.finditer(html_body))

        if keyword_matches > 0:
            score += keyword_matches * 0.5
            indicators.append(f"Found {keyword_matches} spam keyword matches")

        # Check for excessive links
        link_count = 0
        if text_body:
            link_count += sum(1 for _ in self.LINK_PATTERN.finditer(text_body))
        if html_body:
            link_count += sum(1 for _ in self.LINK_PATTERN.finditer(html_body))

        if link_count > 10:
            score += 1.0
            indicators.append(f"Excessive links ({link_count})")

        # Check for image-only emails (common in spam)
        if html_body and len(text_body.strip()) < 50:
            # Only check HTML for img tags, case-insensitive
            img_count = sum(1 for _ in self.IMG_TAG_PATTERN.finditer(html_body))
            if img_count > 2:
                score += 1.0
                indicators.append("Image-heavy email with little text")

        # Check for hidden text (common spam technique)
        if html_body:
            # Look for text with very small font or matching background color
            if self.HIDDEN_TEXT_PATTERN.search(html_body):
                score += 2.0
                indicators.append("Hidden text detected")

        return score, indicators

    def _check_urls(self, content: str) -> Tuple[float, List[str]]:
        """Check for suspicious URLs"""
        score = 0.0
        suspicious = []

        # Extract URLs
        # Using findall here because we need the actual strings to parse
        urls = self.URL_EXTRACTION_PATTERN.findall(content)

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc

                # Check against combined suspicious patterns first
                if self.COMBINED_URL_PATTERN.search(domain):
                     # If matched, we just mark it. The original code broke after first match
                     # in the loop, effectively counting only one match per URL from this list.
                     score += 0.5
                     suspicious.append(url)

                # Check for URL shorteners
                # Original code logic was separate and could add another 0.5 score
                if self.SHORTENER_PATTERN.search(domain):
                    score += 0.5
                    suspicious.append(url)

            except Exception:
                pass

        return score, suspicious

    def _analyze_headers(self, headers: Dict[str, Union[str, List[str]]]) -> Tuple[float, List[str]]:
        """Analyze email headers for anomalies"""
        score = 0.0
        issues = []

        # Helper to always get a list
        def get_header_list(key: str) -> List[str]:
            val = headers.get(key, [])
            if isinstance(val, str):
                return [val]
            return val

        # Check SPF
        spf_headers = get_header_list('received-spf')
        spf_fail = False
        spf_softfail = False
        for spf in spf_headers:
            spf_lower = spf.lower()
            if 'fail' in spf_lower and 'softfail' not in spf_lower:
                spf_fail = True
            elif 'softfail' in spf_lower:
                spf_softfail = True

        if spf_fail:
            score += 2.0
            issues.append("SPF check failed")
        elif spf_softfail:
            score += 1.0
            issues.append("SPF soft fail")

        # Check DKIM
        dkim = get_header_list('dkim-signature')
        if not dkim:
            score += 0.5
            issues.append("Missing DKIM signature")

        # Check for missing standard headers
        # We check for lowercased keys
        required_headers = ['from', 'to', 'date', 'message-id']
        for header in required_headers:
            if header not in headers:
                # Display original case for readability
                display_header = header.title().replace('Id', 'ID')
                score += 0.5
                issues.append(f"Missing {display_header} header")

        # Check for suspicious received headers
        received_headers = get_header_list('received')
        if len(received_headers) > 10:
            score += 1.0
            issues.append("Excessive hops in delivery path")

        # Check for forged sender
        from_headers = get_header_list('from')
        return_path_headers = get_header_list('return-path')

        if len(from_headers) > 1:
            score += 2.0
            issues.append("Multiple From headers detected")

        if from_headers and return_path_headers:
            from_header = from_headers[0].lower()
            return_path = return_path_headers[0].lower()

            # Extract email addresses
            from_email = self.EMAIL_ADDRESS_PATTERN.search(from_header)
            return_email = self.EMAIL_ADDRESS_PATTERN.search(return_path)

            if from_email and return_email:
                if from_email.group() != return_email.group():
                    score += 1.5
                    issues.append("From and Return-Path mismatch")

        return score, issues

    def _check_sender(self, sender: str, headers: Dict[str, Union[str, List[str]]]) -> Tuple[float, List[str]]:
        """Check sender reputation and authenticity"""
        score = 0.0
        indicators = []

        sender_lower = sender.lower()

        # Check for freemail providers (common in spam)
        freemail_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'mail.com', 'protonmail.com'
        ]

        # Extract domain from sender
        email_match = self.SENDER_DOMAIN_PATTERN.search(sender_lower)
        if email_match:
            domain = email_match.group(1)

            # Check if corporate email is from freemail (red flag)
            if any(corp in sender_lower for corp in ['ceo', 'president', 'director', 'manager']):
                if any(provider in domain for provider in freemail_providers):
                    score += 1.5
                    indicators.append("Corporate title with freemail provider")

        # Check for display name mismatch
        display_name_match = self.DISPLAY_NAME_PATTERN.search(sender)
        if display_name_match:
            display_name = display_name_match.group(1).strip().lower()

            # Check if display name contains different domain
            if '@' in display_name or '.' in display_name:
                score += 1.0
                indicators.append("Suspicious display name format")

        return score, indicators

    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level based on spam score"""
        if score >= self.config.spam_threshold * 2:
            return "high"
        elif score >= self.config.spam_threshold:
            return "medium"
        else:
            return "low"
