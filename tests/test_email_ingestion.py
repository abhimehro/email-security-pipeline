"""
Unit tests for src/modules/email_ingestion.py.

Tests cover:
- Module exports and backward compatibility
- EmailIngestionConfig dataclass initialization and defaults
- FetchContext dataclass initialization
- IMAPClient initialization, properties, and configuration synchronization
- IMAPClient connection management (SSL, non-SSL/STARTTLS, auth tips, exceptions)
- IMAPClient folder operations (list_folders, select_folder)
- IMAPClient email fetching (fetch_unseen_emails, failure paths)
- IMAPClient email parsing (parse_email and limit synchronization)
- IMAPClient diagnostics (diagnose_connection_issues)
- IMAPClient backward-compatible static methods
"""

import imaplib
import logging
import ssl
import unittest
from unittest.mock import MagicMock, patch

from src.modules.email_data import EmailData
from src.modules.email_ingestion import (
    EmailIngestionConfig,
    EmailIngestionManager,
    FetchContext,
    IMAPClient,
    __all__,
)
from src.utils.config import EmailAccountConfig


def _make_config(**overrides) -> EmailAccountConfig:
    """Helper to create an EmailAccountConfig for tests."""
    defaults = {
        "enabled": True,
        "email": "test@example.com",
        "imap_server": "imap.example.com",
        "imap_port": 993,
        "app_password": "test-password",
        "folders": ["INBOX"],
        "provider": "generic",
        "use_ssl": True,
    }
    defaults.update(overrides)
    return EmailAccountConfig(**defaults)


class TestEmailIngestionExports(unittest.TestCase):
    """Verify module exports and backward compatibility."""

    def test_module_all_exports(self):
        """__all__ should export the public facade classes."""
        self.assertIn("IMAPClient", __all__)
        self.assertIn("EmailIngestionManager", __all__)
        self.assertIn("EmailData", __all__)


class TestEmailIngestionConfig(unittest.TestCase):
    """Tests for EmailIngestionConfig dataclass."""

    def test_default_config_values(self):
        """Default configuration should specify sensible security limits."""
        config = EmailIngestionConfig()
        self.assertEqual(config.rate_limit_delay, 1)
        self.assertEqual(config.max_attachment_bytes, 25 * 1024 * 1024)
        self.assertEqual(config.max_total_attachment_bytes, 100 * 1024 * 1024)
        self.assertEqual(config.max_attachment_count, 10)
        self.assertEqual(config.max_body_size_bytes, 1024 * 1024)
        self.assertEqual(config.max_parallel_accounts, 3)

    def test_custom_config_values(self):
        """Custom configuration values should be properly assigned."""
        config = EmailIngestionConfig(
            rate_limit_delay=5,
            max_attachment_bytes=5 * 1024 * 1024,
            max_total_attachment_bytes=20 * 1024 * 1024,
            max_attachment_count=3,
            max_body_size_bytes=512 * 1024,
            max_parallel_accounts=8,
        )
        self.assertEqual(config.rate_limit_delay, 5)
        self.assertEqual(config.max_attachment_bytes, 5 * 1024 * 1024)
        self.assertEqual(config.max_total_attachment_bytes, 20 * 1024 * 1024)
        self.assertEqual(config.max_attachment_count, 3)
        self.assertEqual(config.max_body_size_bytes, 512 * 1024)
        self.assertEqual(config.max_parallel_accounts, 8)


class TestFetchContext(unittest.TestCase):
    """Tests for FetchContext dataclass."""

    def test_fetch_context_initialization(self):
        """FetchContext should retain its constructor arguments."""
        account = _make_config()
        client = MagicMock()
        ctx = FetchContext(
            account=account,
            folder="Archive",
            client=client,
            is_first=False,
            max_per_folder=25,
        )
        self.assertEqual(ctx.account, account)
        self.assertEqual(ctx.folder, "Archive")
        self.assertEqual(ctx.client, client)
        self.assertFalse(ctx.is_first)
        self.assertEqual(ctx.max_per_folder, 25)


class TestIMAPClientInitializationAndProperties(unittest.TestCase):
    """Tests for IMAPClient initialization, configuration propagation, and logger properties."""

    def test_init_with_default_ingestion_config(self):
        """IMAPClient should use default EmailIngestionConfig when none provided."""
        account_config = _make_config()
        client = IMAPClient(account_config)

        self.assertEqual(client.config, account_config)
        self.assertEqual(client.rate_limit_delay, 1)
        self.assertEqual(client.max_attachment_bytes, 25 * 1024 * 1024)
        self.assertEqual(client.max_total_attachment_bytes, 100 * 1024 * 1024)
        self.assertEqual(client.max_attachment_count, 10)
        self.assertEqual(client.max_body_size, 1024 * 1024)
        self.assertIsNone(client.connection)
        self.assertIsNotNone(client.connection_manager)
        self.assertIsNotNone(client.parser)

    def test_init_with_custom_ingestion_config(self):
        """IMAPClient should use provided EmailIngestionConfig limits."""
        account_config = _make_config()
        custom_ingestion = EmailIngestionConfig(
            rate_limit_delay=2,
            max_attachment_bytes=10 * 1024 * 1024,
            max_total_attachment_bytes=40 * 1024 * 1024,
            max_attachment_count=5,
        )
        client = IMAPClient(account_config, custom_ingestion)

        self.assertEqual(client.rate_limit_delay, 2)
        self.assertEqual(client.max_attachment_bytes, 10 * 1024 * 1024)
        self.assertEqual(client.max_total_attachment_bytes, 40 * 1024 * 1024)
        self.assertEqual(client.max_attachment_count, 5)

    def test_logger_property_syncs_with_subcomponents(self):
        """Setting logger on IMAPClient propagates the logger to connection_manager and parser."""
        client = IMAPClient(_make_config())
        custom_logger = logging.getLogger("CustomTestLogger")

        client.logger = custom_logger

        self.assertIs(client.logger, custom_logger)
        self.assertIs(client.connection_manager.logger, custom_logger)
        self.assertIs(client.parser.logger, custom_logger)


class TestIMAPClientConnection(unittest.TestCase):
    """Tests for IMAPClient.connect, ensure_connection, and disconnect."""

    def setUp(self):
        self.account_config = _make_config()
        self.client = IMAPClient(self.account_config)
        self.client.logger = MagicMock()

    @patch.object(IMAPClient, "_create_secure_ssl_context")
    @patch("src.modules.email_ingestion.imaplib.IMAP4_SSL")
    def test_connect_ssl_success(self, mock_imap_ssl_cls, mock_ssl_ctx):
        """SSL connection should use IMAP4_SSL with timeout and login properly."""
        mock_conn = MagicMock()
        mock_imap_ssl_cls.return_value = mock_conn

        result = self.client.connect()

        self.assertTrue(result)
        mock_imap_ssl_cls.assert_called_once_with(
            self.account_config.imap_server,
            self.account_config.imap_port,
            ssl_context=mock_ssl_ctx.return_value,
            timeout=30,
        )
        mock_conn.login.assert_called_once_with(
            self.account_config.email, self.account_config.app_password
        )
        self.assertIs(self.client.connection, mock_conn)
        self.assertIs(self.client.connection_manager.connection, mock_conn)

    @patch.object(IMAPClient, "_create_secure_ssl_context")
    @patch("src.modules.email_ingestion.imaplib.IMAP4")
    def test_connect_starttls_success(self, mock_imap_cls, mock_ssl_ctx):
        """Non-SSL connection should use IMAP4, invoke starttls with context, and login."""
        non_ssl_config = _make_config(use_ssl=False, imap_port=143)
        client = IMAPClient(non_ssl_config)
        client.logger = MagicMock()

        mock_conn = MagicMock()
        mock_imap_cls.return_value = mock_conn

        result = client.connect()

        self.assertTrue(result)
        mock_imap_cls.assert_called_once_with(
            non_ssl_config.imap_server,
            non_ssl_config.imap_port,
            timeout=30,
        )
        mock_conn.starttls.assert_called_once_with(ssl_context=mock_ssl_ctx.return_value)
        mock_conn.login.assert_called_once_with(
            non_ssl_config.email, non_ssl_config.app_password
        )
        self.assertIs(client.connection, mock_conn)
        self.assertIs(client.connection_manager.connection, mock_conn)

    @patch.object(IMAPClient, "_create_secure_ssl_context")
    @patch("src.modules.email_ingestion.imaplib.IMAP4_SSL")
    def test_connect_imap_error_with_auth_tip(self, mock_imap_ssl_cls, mock_ssl_ctx):
        """IMAP4.error during connect should log error and display auth tip if available."""
        mock_imap_ssl_cls.side_effect = imaplib.IMAP4.error("Invalid credentials")

        with patch.object(
            self.client.connection_manager,
            "_get_auth_tip",
            return_value="Check App Password",
        ):
            result = self.client.connect()

        self.assertFalse(result)
        self.client.logger.error.assert_called()
        self.client.logger.warning.assert_called_with("💡 Check App Password")

    @patch.object(IMAPClient, "_create_secure_ssl_context")
    @patch("src.modules.email_ingestion.imaplib.IMAP4_SSL")
    def test_connect_generic_exception(self, mock_imap_ssl_cls, mock_ssl_ctx):
        """Generic unexpected exception during connect should be caught and logged."""
        mock_imap_ssl_cls.side_effect = ConnectionResetError("Connection lost")

        result = self.client.connect()

        self.assertFalse(result)
        self.client.logger.error.assert_called()

    def test_ensure_connection_delegates_and_syncs(self):
        """ensure_connection should delegate to connection_manager and sync connection attribute."""
        mock_conn = MagicMock()
        self.client.connection_manager.ensure_connection = MagicMock(return_value=True)
        self.client.connection_manager.connection = mock_conn

        result = self.client.ensure_connection()

        self.assertTrue(result)
        self.assertIs(self.client.connection, mock_conn)
        self.client.connection_manager.ensure_connection.assert_called_once()

    def test_disconnect_clears_connection(self):
        """disconnect should delegate to connection_manager and set self.connection to None."""
        self.client.connection = MagicMock()
        self.client.connection_manager.disconnect = MagicMock()

        self.client.disconnect()

        self.client.connection_manager.disconnect.assert_called_once()
        self.assertIsNone(self.client.connection)


class TestIMAPClientFolderAndFetchOperations(unittest.TestCase):
    """Tests for IMAPClient folder listing, selecting, and fetching emails."""

    def setUp(self):
        self.client = IMAPClient(_make_config())
        self.client.logger = MagicMock()
        self.client.connection = MagicMock()

    def test_list_folders_delegates_to_connection_manager(self):
        """list_folders should delegate directly to connection_manager.list_folders."""
        expected_folders = ["INBOX", "Sent", "Drafts"]
        self.client.connection_manager.list_folders = MagicMock(
            return_value=expected_folders
        )

        folders = self.client.list_folders()

        self.assertEqual(folders, expected_folders)
        self.client.connection_manager.list_folders.assert_called_once()

    def test_select_folder_syncs_connection_and_delegates(self):
        """select_folder should sync connection to connection_manager and return its result."""
        self.client.connection_manager.select_folder = MagicMock(return_value=True)

        result = self.client.select_folder("Archive")

        self.assertTrue(result)
        self.assertIs(self.client.connection_manager.connection, self.client.connection)
        self.client.connection_manager.select_folder.assert_called_once_with("Archive")

    def test_fetch_unseen_emails_select_folder_fails(self):
        """fetch_unseen_emails should return empty list if folder selection fails."""
        with patch.object(self.client, "select_folder", return_value=False):
            result = self.client.fetch_unseen_emails("NonExistent", limit=10)

        self.assertEqual(result, [])

    def test_fetch_unseen_emails_success_delegates_to_internal_fetch(self):
        """fetch_unseen_emails syncs limits and calls _fetch_emails_internal when folder selected."""
        raw_result = [("1", b"raw_email_data")]
        self.client.connection_manager._fetch_emails_internal = MagicMock(
            return_value=raw_result
        )

        with patch.object(self.client, "select_folder", return_value=True):
            result = self.client.fetch_unseen_emails("INBOX", limit=20)

        self.assertEqual(result, raw_result)
        self.assertIs(self.client.connection_manager.connection, self.client.connection)
        self.assertEqual(
            self.client.connection_manager.max_email_size, self.client.max_email_size
        )
        self.client.connection_manager._fetch_emails_internal.assert_called_once_with(
            "INBOX", 20
        )


class TestIMAPClientParsingAndDiagnostics(unittest.TestCase):
    """Tests for IMAPClient.parse_email, diagnose_connection_issues, and static backward-compat methods."""

    def setUp(self):
        self.client = IMAPClient(_make_config())
        self.client.logger = MagicMock()

    def test_parse_email_syncs_limits_and_delegates(self):
        """parse_email should update parser limit attributes before delegating parsing."""
        mock_email_data = MagicMock(spec=EmailData)
        self.client.parser.parse_email = MagicMock(return_value=mock_email_data)

        self.client.max_body_size = 5000
        self.client.max_attachment_bytes = 1000
        self.client.max_total_attachment_bytes = 2000
        self.client.max_attachment_count = 2

        result = self.client.parse_email("101", b"RawEmailBytes", "INBOX")

        self.assertIs(result, mock_email_data)
        self.assertEqual(self.client.parser.max_body_size, 5000)
        self.assertEqual(self.client.parser.max_attachment_bytes, 1000)
        self.assertEqual(self.client.parser.max_total_attachment_bytes, 2000)
        self.assertEqual(self.client.parser.max_attachment_count, 2)
        self.client.parser.parse_email.assert_called_once_with(
            "101", b"RawEmailBytes", "INBOX"
        )

    @patch("src.modules.email_ingestion.IMAPDiagnostics")
    def test_diagnose_connection_issues(self, mock_diag_cls):
        """diagnose_connection_issues creates IMAPDiagnostics and executes diagnose."""
        mock_diag_instance = MagicMock()
        mock_diag_cls.return_value = mock_diag_instance
        expected_report = {"host_resolved": True, "port_open": True}
        mock_diag_instance.diagnose_connection_issues.return_value = expected_report

        report = self.client.diagnose_connection_issues(self.client.config)

        self.assertEqual(report, expected_report)
        mock_diag_cls.assert_called_once_with(self.client.config)
        mock_diag_instance.diagnose_connection_issues.assert_called_once()

    def test_create_secure_ssl_context_static_method(self):
        """_create_secure_ssl_context returns an SSLContext."""
        ctx = IMAPClient._create_secure_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)

    @patch("src.modules.email_ingestion.EmailParser._decode_part_payload")
    def test_decode_part_payload_static_method(self, mock_decode):
        """_decode_part_payload delegates to EmailParser._decode_part_payload."""
        part = MagicMock()
        mock_decode.return_value = b"decoded"

        result = IMAPClient._decode_part_payload(part)

        self.assertEqual(result, b"decoded")
        mock_decode.assert_called_once_with(part)

    @patch("src.modules.email_ingestion.EmailParser._decode_bytes")
    def test_decode_bytes_static_method(self, mock_decode_bytes):
        """_decode_bytes delegates to EmailParser._decode_bytes."""
        mock_decode_bytes.return_value = "decoded_string"

        result = IMAPClient._decode_bytes(b"data", "utf-8")

        self.assertEqual(result, "decoded_string")
        mock_decode_bytes.assert_called_once_with(b"data", "utf-8")


if __name__ == "__main__":
    unittest.main()
