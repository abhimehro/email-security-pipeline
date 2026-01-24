"""
Configuration Management Module
Handles loading and validation of environment variables and settings
"""

import logging
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv
from urllib.parse import urlparse


@dataclass
class EmailAccountConfig:
    """Configuration for a single email account"""
    enabled: bool
    email: str
    imap_server: str
    imap_port: int
    app_password: str = field(repr=False)
    folders: List[str]
    provider: str
    use_ssl: bool
    verify_ssl: bool


@dataclass
class AnalysisConfig:
    """Configuration for analysis layers"""
    # Layer 1: Spam Detection
    spam_threshold: float
    spam_check_headers: bool
    spam_check_urls: bool

    # Layer 2: NLP Threat Detection
    nlp_model: str
    nlp_threshold: float
    nlp_batch_size: int
    check_social_engineering: bool
    check_urgency_markers: bool
    check_authority_impersonation: bool

    # Layer 3: Media Authenticity
    check_media_attachments: bool
    deepfake_detection_enabled: bool
    media_analysis_timeout: int
    deepfake_provider: str
    deepfake_api_key: Optional[str] = field(repr=False)
    deepfake_api_url: Optional[str]
    deepfake_model_path: Optional[str]


@dataclass
class AlertConfig:
    """Configuration for alert system"""
    console: bool
    webhook_enabled: bool
    webhook_url: Optional[str]
    slack_enabled: bool
    slack_webhook: Optional[str]
    threat_low: float
    threat_medium: float
    threat_high: float


@dataclass
class SystemConfig:
    """Configuration for system settings"""
    log_level: str
    log_file: str
    check_interval: int
    max_emails_per_batch: int
    rate_limit_delay: int
    database_enabled: bool
    database_path: Optional[str]
    max_attachment_size_mb: int
    max_total_attachment_size_mb: int
    max_attachment_count: int
    max_body_size_kb: int


class Config:
    """Main configuration class"""

    def __init__(self, env_file: str = ".env"):
        """
        Initialize configuration from environment file

        Args:
            env_file: Path to environment file (default: .env)
        """
        load_dotenv(env_file)

        self.email_accounts = self._load_email_accounts()
        self.analysis = self._load_analysis_config()
        self.alerts = self._load_alert_config()
        self.system = self._load_system_config()

    def _load_email_accounts(self) -> List[EmailAccountConfig]:
        """Load email account configurations"""
        accounts = []

        # Gmail
        if self._get_bool("GMAIL_ENABLED", False):
            accounts.append(EmailAccountConfig(
                enabled=True,
                email=os.getenv("GMAIL_EMAIL", ""),
                imap_server=os.getenv("GMAIL_IMAP_SERVER", "imap.gmail.com"),
                imap_port=int(os.getenv("GMAIL_IMAP_PORT", "993")),
                app_password=os.getenv("GMAIL_APP_PASSWORD", ""),
                folders=self._parse_folders(os.getenv("GMAIL_FOLDERS", "INBOX")),
                provider="gmail",
                use_ssl=self._get_bool("GMAIL_USE_SSL", True),
                verify_ssl=self._get_bool("GMAIL_VERIFY_SSL", True)
            ))

        # Outlook
        if self._get_bool("OUTLOOK_ENABLED", False):
            accounts.append(EmailAccountConfig(
                enabled=True,
                email=os.getenv("OUTLOOK_EMAIL", ""),
                imap_server=os.getenv("OUTLOOK_IMAP_SERVER", "outlook.office365.com"),
                imap_port=int(os.getenv("OUTLOOK_IMAP_PORT", "993")),
                app_password=os.getenv("OUTLOOK_APP_PASSWORD", ""),
                folders=self._parse_folders(os.getenv("OUTLOOK_FOLDERS", "INBOX")),
                provider="outlook",
                use_ssl=self._get_bool("OUTLOOK_USE_SSL", True),
                verify_ssl=self._get_bool("OUTLOOK_VERIFY_SSL", True)
            ))

        # Proton Mail
        if self._get_bool("PROTON_ENABLED", False):
            accounts.append(EmailAccountConfig(
                enabled=True,
                email=os.getenv("PROTON_EMAIL", ""),
                imap_server=os.getenv("PROTON_IMAP_SERVER", "127.0.0.1"),
                imap_port=int(os.getenv("PROTON_IMAP_PORT", "1143")),
                app_password=os.getenv("PROTON_APP_PASSWORD", ""),
                folders=self._parse_folders(os.getenv("PROTON_FOLDERS", "INBOX")),
                provider="proton",
                use_ssl=self._get_bool("PROTON_USE_SSL", True),
                verify_ssl=self._get_bool("PROTON_VERIFY_SSL", True)
            ))

        return accounts

    def _load_analysis_config(self) -> AnalysisConfig:
        """Load analysis configuration"""
        return AnalysisConfig(
            spam_threshold=float(os.getenv("SPAM_THRESHOLD", "5.0")),
            spam_check_headers=self._get_bool("SPAM_CHECK_HEADERS", True),
            spam_check_urls=self._get_bool("SPAM_CHECK_URLS", True),
            nlp_model=os.getenv("NLP_MODEL", "distilbert-base-uncased"),
            nlp_threshold=float(os.getenv("NLP_THRESHOLD", "0.7")),
            nlp_batch_size=int(os.getenv("NLP_BATCH_SIZE", "8")),
            check_social_engineering=self._get_bool("CHECK_SOCIAL_ENGINEERING", True),
            check_urgency_markers=self._get_bool("CHECK_URGENCY_MARKERS", True),
            check_authority_impersonation=self._get_bool("CHECK_AUTHORITY_IMPERSONATION", True),
            check_media_attachments=self._get_bool("CHECK_MEDIA_ATTACHMENTS", True),
            deepfake_detection_enabled=self._get_bool("DEEPFAKE_DETECTION_ENABLED", True),
            media_analysis_timeout=int(os.getenv("MEDIA_ANALYSIS_TIMEOUT", "60")),
            deepfake_provider=os.getenv("DEEPFAKE_PROVIDER", "simulator"),
            deepfake_api_key=os.getenv("DEEPFAKE_API_KEY"),
            deepfake_api_url=os.getenv("DEEPFAKE_API_URL"),
            deepfake_model_path=os.getenv("DEEPFAKE_MODEL_PATH")
        )

    def _load_alert_config(self) -> AlertConfig:
        """Load alert configuration"""
        return AlertConfig(
            console=self._get_bool("ALERT_CONSOLE", True),
            webhook_enabled=self._get_bool("ALERT_WEBHOOK_ENABLED", False),
            webhook_url=os.getenv("ALERT_WEBHOOK_URL"),
            slack_enabled=self._get_bool("ALERT_SLACK_ENABLED", False),
            slack_webhook=os.getenv("ALERT_SLACK_WEBHOOK"),
            threat_low=float(os.getenv("THREAT_LOW", "30.0")),
            threat_medium=float(os.getenv("THREAT_MEDIUM", "60.0")),
            threat_high=float(os.getenv("THREAT_HIGH", "80.0"))
        )

    def _load_system_config(self) -> SystemConfig:
        """Load system configuration"""
        return SystemConfig(
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE", "logs/email_security.log"),
            check_interval=int(os.getenv("CHECK_INTERVAL", "300")),
            max_emails_per_batch=int(os.getenv("MAX_EMAILS_PER_BATCH", "50")),
            rate_limit_delay=int(os.getenv("RATE_LIMIT_DELAY", "1")),
            database_enabled=self._get_bool("DATABASE_ENABLED", False),
            database_path=os.getenv("DATABASE_PATH"),
            max_attachment_size_mb=int(os.getenv("MAX_ATTACHMENT_SIZE_MB", "25")),
            max_total_attachment_size_mb=int(os.getenv("MAX_TOTAL_ATTACHMENT_SIZE_MB", "100")),
            max_attachment_count=int(os.getenv("MAX_ATTACHMENT_COUNT", "10")),
            max_body_size_kb=int(os.getenv("MAX_BODY_SIZE_KB", "1024"))  # Default 1MB limit for body text
        )

    @staticmethod
    def _parse_folders(value: str) -> List[str]:
        """
        Normalize folder string into a clean list.
        Supports both comma-separated and newline-separated folder lists.

        Args:
            value: Folder string (comma or newline separated)

        Returns:
            List of folder names, defaulting to ["INBOX"] if empty
        """
        if not value:
            return ["INBOX"]

        # Replace newlines with commas, then split and clean
        folders = [
            folder.strip()
            for folder in value.replace("\n", ",").split(",")
            if folder.strip()
        ]
        return folders or ["INBOX"]

    @staticmethod
    def _get_bool(key: str, default: bool = False) -> bool:
        """Convert environment variable to boolean"""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')

    @staticmethod
    def _is_https_url(value: str) -> bool:
        try:
            parsed = urlparse(value)
        except ValueError:
            return False
        return parsed.scheme == "https" and bool(parsed.netloc)

    def validate(self) -> bool:
        """
        Validate configuration

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.email_accounts:
            raise ValueError("No email accounts configured. Enable at least one account.")

        for account in self.email_accounts:
            if not account.email or not account.app_password:
                raise ValueError(f"Missing credentials for {account.provider} account")
            if not account.folders:
                raise ValueError(f"No folders configured for {account.provider} account")
            if account.imap_port <= 0:
                raise ValueError(f"Invalid IMAP port for {account.provider} account")

        if self.alerts.webhook_enabled:
            if not self.alerts.webhook_url:
                raise ValueError("Webhook enabled but no URL provided")
            if not self._is_https_url(self.alerts.webhook_url):
                raise ValueError("Webhook URL must use HTTPS")

        if self.alerts.slack_enabled:
            if not self.alerts.slack_webhook:
                raise ValueError("Slack alerts enabled but no webhook URL provided")
            if not self._is_https_url(self.alerts.slack_webhook):
                raise ValueError("Slack webhook URL must use HTTPS")
            if "hooks.slack.com" not in self.alerts.slack_webhook:
                raise ValueError("Slack webhook URL must be a valid Slack hooks endpoint")

        if self.system.max_attachment_size_mb <= 0:
            raise ValueError("MAX_ATTACHMENT_SIZE_MB must be greater than zero")

        if getattr(logging, self.system.log_level.upper(), None) is None:
            raise ValueError(f"Invalid log level: {self.system.log_level}")

        if not (self.alerts.threat_low < self.alerts.threat_medium < self.alerts.threat_high):
            raise ValueError(
                f"Threat thresholds must satisfy LOW < MEDIUM < HIGH. "
                f"Got: LOW={self.alerts.threat_low}, MEDIUM={self.alerts.threat_medium}, HIGH={self.alerts.threat_high}"
            )

        return True
