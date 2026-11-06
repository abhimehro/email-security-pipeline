"""
Regression tests for launchd wrapper script environment validation, .env directory corruption guard,
KeepAlive configuration in plist, and secure pinned TLS CA & hostname validation in Config and SSLContext.

SECURITY & OPERATIONAL RATIONALE:
- Prevents Docker bind-mount auto-creation of .env/ directories from breaking application startup.
- Enforces strict path traversal checks (CWE-22) and SSRF allowlists (ALLOWED_MAIL_SERVER_HOSTS) for TLS CA files and hostnames.
- Ensures SSLContext maintains CERT_REQUIRED and check_hostname=True while supporting pinned CAs and custom hostnames.
"""

import os
import plistlib
import secrets
import ssl
import subprocess  # nosec B404
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.utils.config import Config, ConfigurationError
from src.utils.security_validators import create_secure_ssl_context

_TEST_SECRET = secrets.token_hex(16)


class TestLaunchdAndEnvDirectory(unittest.TestCase):
    def test_start_script_env_directory(self) -> None:
        """
        Test that start-email-security-pipeline.sh fails fast with exit 1 and prints
        'is a directory' when .env is a directory, without invoking Docker.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            env_dir = tmp_path / ".env"
            env_dir.mkdir()

            script_path = (
                Path(__file__).resolve().parents[1]
                / "launchd/start-email-security-pipeline.sh"
            )
            result = subprocess.run(  # nosec B603
                ["/bin/zsh", str(script_path)],
                env={**os.environ, "PROJECT_DIR": str(tmp_path), "HOME": str(tmp_path)},
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertTrue(
                "is a directory" in result.stderr or "is a directory" in result.stdout
            )

    def test_start_script_env_missing(self) -> None:
        """
        Test that start-email-security-pipeline.sh fails fast with exit 1 and prints
        'not found' when .env does not exist, leaving .env non-existent.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            env_file = tmp_path / ".env"
            self.assertFalse(env_file.exists())

            script_path = (
                Path(__file__).resolve().parents[1]
                / "launchd/start-email-security-pipeline.sh"
            )
            result = subprocess.run(  # nosec B603
                ["/bin/zsh", str(script_path)],
                env={**os.environ, "PROJECT_DIR": str(tmp_path), "HOME": str(tmp_path)},
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 1)
            self.assertTrue(
                "not found" in result.stderr or "not found" in result.stdout
            )
            self.assertFalse(env_file.exists())

    def test_plist_keepalive_configuration(self) -> None:
        """
        Test that the launchd plist file configures KeepAlive with SuccessfulExit=False
        rather than unconditional True, preventing infinite restart loops upon clean exit.
        """
        plist_path = (
            Path(__file__).resolve().parents[1]
            / "launchd/com.abhimehrotra.email-security-pipeline.plist"
        )
        with plist_path.open("rb") as f:
            data = plistlib.load(f)

        self.assertEqual(data.get("KeepAlive"), {"SuccessfulExit": False})

    def test_config_env_directory_validation(self) -> None:
        """
        Test that Config constructor and validate() reject .env when it is a directory,
        raising ConfigurationError with an appropriate message.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            env_dir = tmp_path / ".env"
            env_dir.mkdir()

            with patch.dict(os.environ, {}, clear=True):
                cfg = Config(str(env_dir))
                with self.assertRaises(ConfigurationError) as exc_info:
                    cfg.validate()

                err_messages = str(exc_info.exception)
                self.assertIn("directory", err_messages.lower())

    def test_tls_ca_and_hostname_validation(self) -> None:
        """
        Test TLS CA file path traversal prevention (CWE-22), missing file rejection,
        and server hostname allowlist validation in Config and SSLContext creation.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            orig_dir = os.getcwd()
            os.chdir(tmp_path)
            try:
                ca_file = tmp_path / "test_ca.pem"
                ca_file.write_text("fake cert content")

                outside_file = tmp_path.parent / "outside.pem"
                outside_file.write_text("fake")

                env_content = f"""
PROTON_ENABLED=true
PROTON_EMAIL=test@pm.me
PROTON_IMAP_SERVER=127.0.0.1
PROTON_IMAP_PORT=1143
PROTON_APP_PASSWORD={_TEST_SECRET}
PROTON_FOLDERS=INBOX
PROTON_USE_SSL=true
PROTON_TLS_CA_FILE={outside_file}
"""
                env_path = tmp_path / ".env"
                env_path.write_text(env_content)

                with patch.dict(os.environ, {}, clear=True):
                    cfg = Config(str(env_path))
                    with self.assertRaises(ConfigurationError) as exc_info:
                        cfg.validate()
                    errs1 = (
                        exc_info.exception.args[0]
                        if exc_info.exception.args
                        else [str(exc_info.exception)]
                    )
                    self.assertTrue(
                        any(
                            "working tree" in err.lower()
                            or "stay within" in err.lower()
                            for err in errs1
                        )
                    )

                env_content_bad_host = f"""
PROTON_ENABLED=true
PROTON_EMAIL=test@pm.me
PROTON_IMAP_SERVER=127.0.0.1
PROTON_IMAP_PORT=1143
PROTON_APP_PASSWORD={_TEST_SECRET}
PROTON_FOLDERS=INBOX
PROTON_USE_SSL=true
PROTON_TLS_CA_FILE={ca_file.name}
PROTON_TLS_SERVER_HOSTNAME=evil.example.com
"""
                env_path.write_text(env_content_bad_host)
                with patch.dict(os.environ, {}, clear=True):
                    cfg2 = Config(str(env_path))
                    with self.assertRaises(ConfigurationError) as exc_info2:
                        cfg2.validate()
                    errs2 = (
                        exc_info2.exception.args[0]
                        if exc_info2.exception.args
                        else [str(exc_info2.exception)]
                    )
                    self.assertTrue(
                        any("allowed server list" in err.lower() for err in errs2)
                    )

                env_content_valid = f"""
PROTON_ENABLED=true
PROTON_EMAIL=test@pm.me
PROTON_IMAP_SERVER=127.0.0.1
PROTON_IMAP_PORT=1143
PROTON_APP_PASSWORD={_TEST_SECRET}
PROTON_FOLDERS=INBOX
PROTON_USE_SSL=true
PROTON_TLS_CA_FILE={ca_file.name}
PROTON_TLS_SERVER_HOSTNAME=127.0.0.1
"""
                env_path.write_text(env_content_valid)
                with patch.dict(os.environ, {}, clear=True):
                    cfg3 = Config(str(env_path))
                    cfg3.validate()

                    account = cfg3.email_accounts[0]
                    self.assertEqual(account.tls_ca_file, ca_file.name)
                    self.assertEqual(account.tls_server_hostname, "127.0.0.1")

                with patch(
                    "ssl.SSLContext.load_verify_locations"
                ) as mock_load_verify, patch(
                    "ssl.SSLContext.wrap_socket"
                ) as mock_base_wrap_socket:
                    ctx = create_secure_ssl_context(
                        ca_file=account.tls_ca_file,
                        server_hostname=account.tls_server_hostname,
                    )
                    mock_load_verify.assert_called_once()
                    self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
                    self.assertTrue(ctx.check_hostname)
                    self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

                    fake_sock = MagicMock()
                    ctx.wrap_socket(fake_sock, server_hostname="host.docker.internal")
                    mock_base_wrap_socket.assert_called_once_with(
                        fake_sock, False, server_hostname="127.0.0.1"
                    )
            finally:
                os.chdir(orig_dir)

    def test_imap_client_passes_tls_pinning(self) -> None:
        import unittest.mock as mock

        from src.modules.email_ingestion import IMAPClient
        from src.utils.config import EmailAccountConfig

        config = EmailAccountConfig(
            provider="proton",
            email="test@pm.me",
            app_password=_TEST_SECRET,
            imap_server="127.0.0.1",
            imap_port=1143,
            use_ssl=True,
            tls_ca_file="data/proton-bridge-cert.pem",
            tls_server_hostname="127.0.0.1",
            enabled=True,
            folders=["INBOX"],
        )
        client = IMAPClient(config)
        with mock.patch.object(
            client, "_create_secure_ssl_context"
        ) as mock_create_ctx, mock.patch(
            "imaplib.IMAP4_SSL"
        ) as mock_imap_ssl, mock.patch.object(
            client.connection_manager, "connection"
        ):
            mock_create_ctx.return_value = mock.MagicMock()
            mock_imap_inst = mock_imap_ssl.return_value
            mock_imap_inst.login.return_value = ("OK", [b"Logged in"])

            success = client.connect()
            self.assertTrue(success)
            mock_create_ctx.assert_called_once_with(
                ca_file="data/proton-bridge-cert.pem", server_hostname="127.0.0.1"
            )
