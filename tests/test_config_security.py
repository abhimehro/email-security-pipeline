
import unittest
from src.utils.config import EmailAccountConfig, AnalysisConfig, AlertConfig

class TestConfigSecurity(unittest.TestCase):
    def test_alert_config_repr_security(self):
        """Test that AlertConfig __repr__ does not leak webhooks"""
        secret_webhook = "https://hooks.slack.com/services/T000/B000/SECRET"
        secret_url = "https://example.com?token=SECRET"

        config = AlertConfig(
            console=True,
            webhook_enabled=True,
            webhook_url=secret_url,
            slack_enabled=True,
            slack_webhook=secret_webhook,
            threat_low=30.0,
            threat_medium=60.0,
            threat_high=80.0
        )

        repr_str = str(config)
        self.assertNotIn(secret_webhook, repr_str, "Slack webhook leaked in __repr__")
        self.assertNotIn(secret_url, repr_str, "Webhook URL leaked in __repr__")
        self.assertNotIn("slack_webhook", repr_str, "Field name should be hidden")

    def test_email_account_config_repr_security(self):
        """Test that EmailAccountConfig __repr__ does not leak app_password"""
        secret_password = "SUPER_SECRET_PASSWORD_123"
        config = EmailAccountConfig(
            enabled=True,
            email="test@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password=secret_password,
            folders=["INBOX"],
            provider="test",
            use_ssl=True,
            verify_ssl=True
        )

        repr_str = str(config)
        self.assertNotIn(secret_password, repr_str, "Password leaked in __repr__")
        self.assertNotIn("app_password", repr_str, "app_password field name shouldn't be in __repr__ if excluded")

    def test_analysis_config_repr_security(self):
        """Test that AnalysisConfig __repr__ does not leak deepfake_api_key"""
        secret_key = "SECRET_API_KEY_XYZ"
        config = AnalysisConfig(
            spam_threshold=0.5,
            spam_check_headers=True,
            spam_check_urls=True,
            nlp_model="test",
            nlp_threshold=0.5,
            nlp_batch_size=1,
            check_social_engineering=True,
            check_urgency_markers=True,
            check_authority_impersonation=True,
            check_media_attachments=True,
            deepfake_detection_enabled=True,
            media_analysis_timeout=60,
            deepfake_provider="test",
            deepfake_api_key=secret_key,
            deepfake_api_url="http://test",
            deepfake_model_path=None
        )

        repr_str = str(config)
        self.assertNotIn(secret_key, repr_str, "API Key leaked in __repr__")
        self.assertNotIn("deepfake_api_key", repr_str, "deepfake_api_key field name shouldn't be in __repr__ if excluded")

if __name__ == "__main__":
    unittest.main()
