"""Credential and configuration validators."""

from typing import List

from src.utils.config import Config


def _is_placeholder_password(password: str) -> bool:
    """
    Check if a password matches placeholder patterns or is empty.

    Avoids storing hardcoded default passwords in source code.
    """
    if not password or not str(password).strip():
        return True

    val = str(password).strip().lower()
    return val.startswith("your-") and val.endswith("-here")


def check_default_credentials(config: Config) -> List[str]:
    """
    Check if the configuration uses default example values.

    Returns a list of error messages.
    """
    errors = []

    # Default values from .env.example
    DEFAULT_EMAILS = [
        "your-email@gmail.com",
        "your-email@outlook.com",
        "your-email@pm.me",
    ]
    DEFAULT_WEBHOOK = "https://your-webhook-url.com/alerts"
    DEFAULT_SLACK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

    # Check Email Accounts
    for account in config.email_accounts:
        if account.enabled:
            if account.email in DEFAULT_EMAILS:
                errors.append(
                    f"{account.provider.title()} account enabled but uses default email: {account.email}"
                )
            if _is_placeholder_password(account.app_password):
                errors.append(
                    f"{account.provider.title()} account enabled but uses default password"
                )

    # Check Alerts
    if config.alerts.webhook_enabled and config.alerts.webhook_url == DEFAULT_WEBHOOK:
        errors.append("Webhook alerts enabled but uses default URL")

    if config.alerts.slack_enabled and config.alerts.slack_webhook == DEFAULT_SLACK:
        errors.append("Slack alerts enabled but uses default Webhook URL")

    return errors
