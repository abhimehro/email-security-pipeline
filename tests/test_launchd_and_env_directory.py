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
import shutil
import ssl
import subprocess  # nosec B404
import tempfile
import unittest
from itertools import product
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.utils.config import Config, ConfigurationError
from src.utils.security_validators import create_secure_ssl_context

# Generated secret token for tests; prevents hardcoded secret warnings in static analysis.
_TEST_SECRET = secrets.token_hex(16)


class TestLaunchdAndEnvDirectory(unittest.TestCase):
    """Test suite for launchd startup script validation, plist configuration, and TLS pinning."""

    @staticmethod
    def _proton_env(**overrides: str) -> dict[str, str]:
        """Build an in-memory Proton environment mapping for Config validation tests."""
        base = {
            "PROTON_ENABLED": "true",
            "PROTON_EMAIL": "test@pm.me",
            "PROTON_IMAP_SERVER": "127.0.0.1",
            "PROTON_IMAP_PORT": "1143",
            "PROTON_APP_PASSWORD": _TEST_SECRET,
            "PROTON_FOLDERS": "INBOX",
            "PROTON_USE_SSL": "true",
        }
        base.update(overrides)
        return base

    def test_start_script_validations(self) -> None:
        """Test that start-email-security-pipeline.sh fails fast when .env is a directory or missing."""
        zsh = shutil.which("zsh")
        if zsh is None:
            self.skipTest("zsh is unavailable")
        script_path = (
            Path(__file__).resolve().parents[1]
            / "launchd/start-email-security-pipeline.sh"
        )
        scenarios = [
            ("directory", "is a directory"),
            ("missing", "not found"),
        ]
        for (setup_type, expected_msg), relative, absolute_compose in product(
            scenarios, (False, True), (False, True)
        ):
            with self.subTest(
                setup_type=setup_type, relative=relative, absolute_compose=absolute_compose
            ), tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir) / "project"
                tmp_path.mkdir()
                env_path = tmp_path / ".env"
                if setup_type == "directory":
                    env_path.mkdir()
                else:
                    self.assertFalse(env_path.exists())

                result = subprocess.run(  # nosec B603
                    [zsh, str(script_path)],
                    env={
                        **os.environ,
                        "PROJECT_DIR": tmp_path.name if relative else str(tmp_path),
                        "COMPOSE_FILE": (
                            str(Path(tmpdir) / "external-compose.yml")
                            if absolute_compose
                            else "docker-compose.yml"
                        ),
                        "HOME": str(tmp_path),
                    },
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    check=False,
                )

                self.assertEqual(result.returncode, 1)
                self.assertIn(str(env_path.resolve()), result.stderr)
                self.assertTrue(
                    expected_msg in result.stderr or expected_msg in result.stdout
                )
                if setup_type == "missing":
                    self.assertFalse(env_path.exists())

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

            with patch.dict(os.environ, self._proton_env(), clear=True):
                cfg = Config(str(env_dir))
                with self.assertRaises(ConfigurationError) as exc_info:
                    cfg.validate()

                err_messages = str(exc_info.exception)
                self.assertIn("directory", err_messages.lower())

    def test_tls_ca_rejects_path_traversal(self) -> None:
        """Test that TLS CA file paths outside the working tree are rejected (CWE-22)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            orig_dir = os.getcwd()
            os.chdir(tmp_path)
            try:
                outside_file = tmp_path.parent / "outside.pem"
                outside_file.write_text("fake cert content")

                env_map = self._proton_env(PROTON_TLS_CA_FILE=str(outside_file))
                with patch.dict(os.environ, env_map, clear=True):
                    cfg = Config(env_file="nonexistent.env")
                    with self.assertRaises(ConfigurationError) as exc_info:
                        cfg.validate()
                    errs = (
                        exc_info.exception.args[0]
                        if exc_info.exception.args
                        else [str(exc_info.exception)]
                    )
                    self.assertTrue(
                        any(
                            "working tree" in err.lower()
                            or "stay within" in err.lower()
                            for err in errs
                        )
                    )
            finally:
                os.chdir(orig_dir)

    def test_tls_hostname_rejects_disallowed_host(self) -> None:
        """Test that TLS server hostnames not on the allowlist are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            orig_dir = os.getcwd()
            os.chdir(tmp_path)
            try:
                ca_file = tmp_path / "test_ca.pem"
                ca_file.write_text("fake cert content")

                env_map = self._proton_env(
                    PROTON_TLS_CA_FILE=ca_file.name,
                    PROTON_TLS_SERVER_HOSTNAME="evil.example.com",
                )
                with patch.dict(os.environ, env_map, clear=True):
                    cfg = Config(env_file="nonexistent.env")
                    with self.assertRaises(ConfigurationError) as exc_info:
                        cfg.validate()
                    errs = (
                        exc_info.exception.args[0]
                        if exc_info.exception.args
                        else [str(exc_info.exception)]
                    )
                    self.assertTrue(
                        any("allowed server list" in err.lower() for err in errs)
                    )
            finally:
                os.chdir(orig_dir)

    def test_tls_pinning_builds_verified_ssl_context(self) -> None:
        """Test that valid TLS pinning config successfully builds a verified SSLContext with SNI override."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            orig_dir = os.getcwd()
            os.chdir(tmp_path)
            try:
                ca_file = tmp_path / "test_ca.pem"
                ca_file.write_text("fake cert content")

                env_map = self._proton_env(
                    PROTON_TLS_CA_FILE=ca_file.name,
                    PROTON_TLS_SERVER_HOSTNAME="127.0.0.1",
                )
                with patch.dict(os.environ, env_map, clear=True):
                    cfg = Config(env_file="nonexistent.env")
                    cfg.validate()

                    account = cfg.email_accounts[0]
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
                        fake_sock, server_hostname="127.0.0.1"
                    )
            finally:
                os.chdir(orig_dir)

    def test_imap_client_passes_tls_pinning(self) -> None:
        """Test that IMAPClient correctly requests and passes TLS pinning settings to SSL context creation."""
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
