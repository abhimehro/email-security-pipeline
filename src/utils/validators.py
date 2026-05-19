from typing import List

from src.utils.config import Config


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
    DEFAULT_PASSWORDS = ["your-app-password-here", "your-bridge-password-here"]
    DEFAULT_WEBHOOK = "https://your-webhook-url.com/alerts"
    DEFAULT_SLACK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

    # Check Email Accounts
    for account in config.email_accounts:
        if account.enabled:
            if not isinstance(account.email, str):
                msg = (
                    f"{account.provider.title()} account enabled but uses "
                    f"invalid email type: {type(account.email).__name__}"
                )
                errors.append(msg)
            elif account.email in DEFAULT_EMAILS:
                errors.append(
                    f"{account.provider.title()} account enabled but uses "
                    f"default email: {account.email}"
                )

            if not isinstance(account.app_password, str):
                t_name = type(account.app_password).__name__
                msg = (
                    f"{account.provider.title()} account enabled but uses "
                    f"invalid password type: {t_name}"
                )
                errors.append(msg)
            elif account.app_password in DEFAULT_PASSWORDS:
                msg = (
                    f"{account.provider.title()} account enabled but "
                    "uses default password"
                )
                errors.append(msg)

    # Check Alerts
    if config.alerts.webhook_enabled:
        if not isinstance(config.alerts.webhook_url, str):
            msg = (
                "Webhook alerts enabled but uses invalid URL type: "
                f"{type(config.alerts.webhook_url).__name__}"
            )
            errors.append(msg)
        elif config.alerts.webhook_url == DEFAULT_WEBHOOK:
            errors.append("Webhook alerts enabled but uses default URL")

    if config.alerts.slack_enabled:
        if not isinstance(config.alerts.slack_webhook, str):
            msg = (
                "Slack alerts enabled but uses invalid Webhook URL type: "
                f"{type(config.alerts.slack_webhook).__name__}"
            )
            errors.append(msg)
        elif config.alerts.slack_webhook == DEFAULT_SLACK:
            errors.append("Slack alerts enabled but uses default Webhook URL")

    return errors
