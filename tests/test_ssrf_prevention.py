import unittest
from unittest.mock import patch, MagicMock
import socket

from src.utils.security_validators import is_safe_webhook_url
from src.utils.config import Config, ConfigurationError


class TestSSRFPrevention(unittest.TestCase):

    def test_empty_url(self):
        is_safe, msg = is_safe_webhook_url("")
        self.assertFalse(is_safe)
        self.assertIn("empty", msg)

    def test_invalid_scheme(self):
        is_safe, msg = is_safe_webhook_url("ftp://example.com")
        self.assertFalse(is_safe)
        self.assertIn("scheme must be http or https", msg)

    def test_missing_hostname(self):
        is_safe, msg = is_safe_webhook_url("https://")
        self.assertFalse(is_safe)
        self.assertIn("must contain a valid hostname", msg)

    @patch('socket.getaddrinfo')
    def test_resolution_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        is_safe, msg = is_safe_webhook_url("https://nonexistent.local.domain")
        self.assertFalse(is_safe)
        self.assertIn("Could not resolve hostname", msg)

    @patch('socket.getaddrinfo')
    def test_safe_public_ip(self, mock_getaddrinfo):
        # Mock getaddrinfo to return a public IP (e.g., 8.8.8.8)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))
        ]
        is_safe, msg = is_safe_webhook_url("https://api.github.com/webhook")
        self.assertTrue(is_safe)
        self.assertEqual(msg, "")

    @patch('socket.getaddrinfo')
    def test_loopback_ip(self, mock_getaddrinfo):
        # Mock getaddrinfo to return localhost IPv4
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))
        ]
        is_safe, msg = is_safe_webhook_url("https://localhost/webhook")
        self.assertFalse(is_safe)
        self.assertIn("resolves to loopback", msg)

    @patch('socket.getaddrinfo')
    def test_private_ip(self, mock_getaddrinfo):
        # Mock getaddrinfo to return RFC 1918 private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', 443))
        ]
        is_safe, msg = is_safe_webhook_url("https://internal-api.corp/webhook")
        self.assertFalse(is_safe)
        self.assertIn("resolves to private IP", msg)

    @patch('socket.getaddrinfo')
    def test_aws_metadata_ip(self, mock_getaddrinfo):
        # Mock getaddrinfo to return link-local IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))
        ]
        is_safe, msg = is_safe_webhook_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)
        # Note: Depending on the Python version, link-local could also report as private.
        # Check for link-local or private logic to handle `ipaddress` variations
        self.assertTrue(
            "link-local" in msg or "private IP" in msg,
            f"Expected link-local or private error msg, got: {msg}"
        )

    @patch('socket.getaddrinfo')
    def test_zero_net_ip(self, mock_getaddrinfo):
        # Mock getaddrinfo to return 0.0.0.0
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('0.0.0.0', 443))
        ]
        is_safe, msg = is_safe_webhook_url("http://0.0.0.0/webhook")
        self.assertFalse(is_safe)
        # 0.0.0.0 often returns true for `is_private` as well in Python ipaddress
        self.assertTrue(
            "zero-net" in msg or "private IP" in msg,
            f"Expected zero-net or private error msg, got: {msg}"
        )


class TestConfigSSRFPrevention(unittest.TestCase):

    @patch('src.utils.config.load_dotenv')
    @patch('src.utils.config.os.getenv')
    def test_config_webhook_ssrf_prevention(self, mock_getenv, mock_load_dotenv):
        # Setup mock environment variables for a basic valid config
        def getenv_side_effect(key, default=None):
            env_vars = {
                "GMAIL_ENABLED": "true",
                "GMAIL_EMAIL": "test@gmail.com",
                "GMAIL_APP_PASSWORD": "password123",
                "GMAIL_IMAP_SERVER": "imap.gmail.com",
                "GMAIL_IMAP_PORT": "993",
                "GMAIL_FOLDERS": "INBOX",
                "ALERT_WEBHOOK_ENABLED": "true",
                "ALERT_WEBHOOK_URL": "https://localhost/webhook",  # Malicious/Local URL
                "THREAT_LOW": "30.0",
                "THREAT_MEDIUM": "60.0",
                "THREAT_HIGH": "80.0",
                "MAX_ATTACHMENT_SIZE_MB": "25",
                "LOG_ROTATION_SIZE_MB": "10",
                "LOG_ROTATION_KEEP_FILES": "5",
                "LOG_FORMAT": "text",
                "LOG_LEVEL": "INFO",
            }
            return env_vars.get(key, default)

        mock_getenv.side_effect = getenv_side_effect

        # We need to mock getaddrinfo inside the validation call
        with patch('socket.getaddrinfo') as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))
            ]

            config = Config()

            with self.assertRaises(ConfigurationError) as cm:
                config.validate()

            errors = cm.exception.args[0]
            # Ensure the specific SSRF error is in the errors list
            self.assertTrue(any("SSRF check failed" in err for err in errors), "SSRF error not found in ConfigurationError")
            self.assertTrue(any("loopback" in err for err in errors), "Loopback detail not found in ConfigurationError")
