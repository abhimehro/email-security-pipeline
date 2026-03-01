"""
Unit tests for IMAPConnection and IMAPDiagnostics classes

SECURITY STORY: The IMAP connection module is the entry point for all email
analysis. Untested exception paths — auth failures, SSL errors, network
timeouts — can silently break the pipeline or, worse, mask credential leaks.
These tests ensure every failure mode is handled without crashing.

PATTERN RECOGNITION: All network I/O (imaplib, socket, ssl) is mocked so the
tests run without real credentials or network access, matching the rest of the
test suite.
"""

import imaplib
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch, call

from src.modules.imap_connection import IMAPConnection, IMAPDiagnostics
from src.utils.config import EmailAccountConfig


def _make_config(**overrides) -> EmailAccountConfig:
    """Return a minimal EmailAccountConfig suitable for unit tests."""
    defaults = dict(
        enabled=True,
        email="test@example.com",
        imap_server="imap.example.com",
        imap_port=993,
        app_password="secret",
        folders=["INBOX"],
        provider="generic",
        use_ssl=True,
        verify_ssl=True,
    )
    defaults.update(overrides)
    return EmailAccountConfig(**defaults)


class TestIMAPConnectionConnect(unittest.TestCase):
    """Tests for IMAPConnection.connect()"""

    def setUp(self):
        self.config = _make_config()
        self.conn = IMAPConnection(self.config)
        self.conn.logger = MagicMock()

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.imaplib.IMAP4_SSL")
    def test_connect_success_ssl(self, mock_imap4_ssl, mock_ssl_ctx):
        """
        SECURITY STORY: Successful SSL login must call login() with the exact
        credentials from config. Any deviation could mean the wrong account is
        authenticated, bypassing access controls.
        """
        mock_imap = MagicMock()
        mock_imap4_ssl.return_value = mock_imap

        result = self.conn.connect()

        self.assertTrue(result)
        mock_imap4_ssl.assert_called_once_with(
            self.config.imap_server,
            self.config.imap_port,
            ssl_context=mock_ssl_ctx.return_value,
            timeout=30,
        )
        mock_imap.login.assert_called_once_with(
            self.config.email, self.config.app_password
        )
        self.assertEqual(self.conn.connection, mock_imap)

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.imaplib.IMAP4_SSL")
    def test_connect_imap_error_returns_false(self, mock_imap4_ssl, mock_ssl_ctx):
        """
        SECURITY STORY: Authentication failures must return False (not raise),
        so the caller can decide whether to retry or log an alert. Unhandled
        exceptions would crash the pipeline and silently stop monitoring.
        """
        mock_imap4_ssl.side_effect = imaplib.IMAP4.error("authentication failed")

        result = self.conn.connect()

        self.assertFalse(result)
        self.conn.logger.error.assert_called()

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.imaplib.IMAP4_SSL")
    def test_connect_generic_exception_returns_false(self, mock_imap4_ssl, mock_ssl_ctx):
        """Unexpected errors (e.g. network timeout) must also return False safely."""
        mock_imap4_ssl.side_effect = OSError("network unreachable")

        result = self.conn.connect()

        self.assertFalse(result)
        self.conn.logger.error.assert_called()

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.imaplib.IMAP4")
    def test_connect_starttls_when_ssl_disabled(self, mock_imap4, mock_ssl_ctx):
        """When use_ssl=False, connect() must fall back to STARTTLS."""
        config = _make_config(use_ssl=False)
        conn = IMAPConnection(config)
        conn.logger = MagicMock()

        mock_imap = MagicMock()
        mock_imap4.return_value = mock_imap

        result = conn.connect()

        self.assertTrue(result)
        mock_imap.starttls.assert_called_once()
        mock_imap.login.assert_called_once_with(config.email, config.app_password)

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.imaplib.IMAP4_SSL")
    def test_connect_auth_tip_logged_for_gmail(self, mock_imap4_ssl, mock_ssl_ctx):
        """
        INDUSTRY CONTEXT: Gmail requires App Passwords. When authentication
        fails against Gmail, we must log a helpful tip to guide the user.
        """
        config = _make_config(imap_server="imap.gmail.com")
        conn = IMAPConnection(config)
        conn.logger = MagicMock()

        mock_imap4_ssl.side_effect = imaplib.IMAP4.error("authentication failed")

        conn.connect()

        # The warning tip should mention App Password or similar guidance
        warning_calls = [str(c) for c in conn.logger.warning.call_args_list]
        self.assertTrue(
            any("App Password" in w or "2-Step" in w for w in warning_calls),
            f"Expected App Password tip in warnings: {warning_calls}",
        )


class TestIMAPConnectionDisconnect(unittest.TestCase):
    """Tests for IMAPConnection.disconnect()"""

    def setUp(self):
        self.config = _make_config()
        self.conn = IMAPConnection(self.config)
        self.conn.logger = MagicMock()

    def test_disconnect_calls_logout(self):
        """disconnect() must call logout() on the active connection."""
        mock_imap = MagicMock()
        self.conn.connection = mock_imap

        self.conn.disconnect()

        mock_imap.logout.assert_called_once()
        self.assertIsNone(self.conn.connection)

    def test_disconnect_when_already_disconnected(self):
        """
        MAINTENANCE WISDOM: Calling disconnect() twice must be idempotent.
        Pipeline shutdown code should not need to track connection state.
        """
        self.conn.connection = None  # Already disconnected

        # Should not raise
        self.conn.disconnect()
        self.assertIsNone(self.conn.connection)

    def test_disconnect_clears_connection_even_on_logout_error(self):
        """
        SECURITY STORY: Even if logout() raises (e.g. server already closed),
        the local connection reference must be cleared so we don't accidentally
        reuse a broken socket.
        """
        mock_imap = MagicMock()
        mock_imap.logout.side_effect = Exception("already closed")
        self.conn.connection = mock_imap

        self.conn.disconnect()

        self.assertIsNone(self.conn.connection)


class TestIMAPConnectionEnsureConnection(unittest.TestCase):
    """Tests for IMAPConnection.ensure_connection()"""

    def setUp(self):
        self.config = _make_config()
        self.conn = IMAPConnection(self.config)
        self.conn.logger = MagicMock()

    def test_ensure_connection_reconnects_when_none(self):
        """
        INDUSTRY CONTEXT: IMAP connections can time out. ensure_connection()
        must automatically reconnect when the connection is None so callers
        don't have to manage reconnect logic themselves.
        """
        self.conn.connection = None

        with patch.object(self.conn, "connect", return_value=True) as mock_connect:
            result = self.conn.ensure_connection()

        self.assertTrue(result)
        mock_connect.assert_called_once()

    def test_ensure_connection_keeps_alive_when_noop_ok(self):
        """When NOOP succeeds, ensure_connection() must return True without reconnecting."""
        mock_imap = MagicMock()
        mock_imap.noop.return_value = ("OK", [b"Nothing to do."])
        self.conn.connection = mock_imap

        with patch.object(self.conn, "connect") as mock_connect:
            result = self.conn.ensure_connection()

        self.assertTrue(result)
        mock_connect.assert_not_called()

    def test_ensure_connection_reconnects_after_noop_failure(self):
        """
        SECURITY STORY: A dropped connection could cause silent fetch failures.
        ensure_connection() must detect a dead socket (NOOP raises) and reconnect.
        """
        mock_imap = MagicMock()
        mock_imap.noop.side_effect = Exception("connection reset")
        self.conn.connection = mock_imap

        with patch.object(self.conn, "connect", return_value=True) as mock_connect:
            result = self.conn.ensure_connection()

        self.assertTrue(result)
        mock_connect.assert_called_once()


class TestIMAPConnectionListFolders(unittest.TestCase):
    """Tests for IMAPConnection.list_folders()"""

    def setUp(self):
        self.config = _make_config()
        self.conn = IMAPConnection(self.config)
        self.conn.logger = MagicMock()

    def test_list_folders_returns_names(self):
        """list_folders() must parse IMAP LIST responses and return folder names."""
        mock_imap = MagicMock()
        mock_imap.list.return_value = (
            "OK",
            [
                b'(\\HasNoChildren) "/" "INBOX"',
                b'(\\HasNoChildren) "/" "Sent"',
                b'(\\HasNoChildren) "/" "Spam"',
            ],
        )
        self.conn.connection = mock_imap

        folders = self.conn.list_folders()

        self.assertIn("INBOX", folders)
        self.assertIn("Sent", folders)
        self.assertIn("Spam", folders)

    def test_list_folders_no_connection_returns_empty(self):
        """list_folders() must return [] when there is no active connection."""
        self.conn.connection = None

        folders = self.conn.list_folders()

        self.assertEqual(folders, [])

    def test_list_folders_on_exception_returns_empty(self):
        """list_folders() must return [] and log an error if list() raises."""
        mock_imap = MagicMock()
        mock_imap.list.side_effect = Exception("socket error")
        self.conn.connection = mock_imap

        folders = self.conn.list_folders()

        self.assertEqual(folders, [])
        self.conn.logger.error.assert_called()


class TestIMAPConnectionSelectFolder(unittest.TestCase):
    """Tests for IMAPConnection.select_folder()"""

    def setUp(self):
        self.config = _make_config()
        self.conn = IMAPConnection(self.config)
        self.conn.logger = MagicMock()

    def test_select_folder_success(self):
        """select_folder() must return True when the IMAP server responds OK."""
        mock_imap = MagicMock()
        mock_imap.select.return_value = ("OK", [b"5"])
        self.conn.connection = mock_imap

        result = self.conn.select_folder("INBOX")

        self.assertTrue(result)
        mock_imap.select.assert_called_once_with("INBOX")

    def test_select_folder_imap_no_status_returns_false(self):
        """
        SECURITY STORY: A non-OK status (e.g. NO or BAD) means the server
        rejected the folder. We must return False so the caller skips
        processing that folder instead of silently fetching nothing.
        """
        mock_imap = MagicMock()
        mock_imap.select.return_value = ("NO", [b"Folder does not exist"])
        self.conn.connection = mock_imap

        result = self.conn.select_folder("NonExistent")

        self.assertFalse(result)

    def test_select_folder_exception_returns_false(self):
        """select_folder() must return False and log an error if select() raises."""
        mock_imap = MagicMock()
        mock_imap.select.side_effect = imaplib.IMAP4.error("permission denied")
        self.conn.connection = mock_imap

        result = self.conn.select_folder("INBOX")

        self.assertFalse(result)
        self.conn.logger.error.assert_called()

    def test_select_folder_no_connection_returns_false(self):
        """select_folder() must return False immediately when not connected."""
        self.conn.connection = None

        result = self.conn.select_folder("INBOX")

        self.assertFalse(result)


class TestIMAPConnectionCheckEmailSizes(unittest.TestCase):
    """Tests for IMAPConnection._check_email_sizes()"""

    def setUp(self):
        self.config = _make_config()
        # Use a small max size so we can test filtering easily
        self.conn = IMAPConnection(self.config, max_total_attachment_bytes=1024)
        self.conn.logger = MagicMock()

    def test_check_email_sizes_filters_oversized(self):
        """
        SECURITY STORY: DoS prevention — emails larger than the configured
        limit must be excluded before downloading to avoid filling memory or
        disk with attacker-controlled data.
        """
        # Two emails: one small (safe), one enormous (rejected)
        mock_imap = MagicMock()
        mock_imap.fetch.return_value = (
            "OK",
            [
                b"1 (RFC822.SIZE 512)",     # 512 bytes — well under limit
                b"2 (RFC822.SIZE 99999999)",  # ~95 MB — over any reasonable limit
            ],
        )
        self.conn.connection = mock_imap

        safe = self.conn._check_email_sizes([b"1", b"2"])

        # Only the small email should survive
        self.assertIn(b"1", safe)
        self.assertNotIn(b"2", safe)
        self.conn.logger.warning.assert_called()

    def test_check_email_sizes_all_safe_included(self):
        """All emails under the size limit must be returned unchanged."""
        mock_imap = MagicMock()
        mock_imap.fetch.return_value = (
            "OK",
            [
                b"1 (RFC822.SIZE 100)",
                b"2 (RFC822.SIZE 200)",
            ],
        )
        self.conn.connection = mock_imap

        safe = self.conn._check_email_sizes([b"1", b"2"])

        self.assertIn(b"1", safe)
        self.assertIn(b"2", safe)

    def test_check_email_sizes_empty_on_fetch_error(self):
        """_check_email_sizes() must return [] and log an error if fetch() raises."""
        mock_imap = MagicMock()
        mock_imap.fetch.side_effect = Exception("connection reset")
        self.conn.connection = mock_imap

        safe = self.conn._check_email_sizes([b"1"])

        self.assertEqual(safe, [])
        self.conn.logger.error.assert_called()


class TestIMAPDiagnosticsServerReachability(unittest.TestCase):
    """Tests for IMAPDiagnostics._check_server_reachability()"""

    def setUp(self):
        self.config = _make_config()
        self.diag = IMAPDiagnostics(self.config)
        self.diag.logger = MagicMock()

    @patch("src.modules.imap_connection.socket.gethostbyname")
    def test_reachable_server_returns_ip(self, mock_gethostbyname):
        """
        SECURITY STORY: DNS resolution is the first step in detecting server
        impersonation. A valid resolution gives us the IP to compare against
        expected ranges. This path must record the resolved address.
        """
        mock_gethostbyname.return_value = "93.184.216.34"

        result = self.diag._check_server_reachability()

        self.assertTrue(result["host_resolved"])
        self.assertEqual(result["resolves_to"], "93.184.216.34")
        self.assertIsNone(result["error"])

    @patch("src.modules.imap_connection.socket.gethostbyname")
    def test_unreachable_server_records_error(self, mock_gethostbyname):
        """DNS failure (gaierror) must be caught and reported without crashing."""
        mock_gethostbyname.side_effect = socket.gaierror("Name or service not known")

        result = self.diag._check_server_reachability()

        self.assertFalse(result["host_resolved"])
        self.assertIn("DNS lookup failed", result["error"])


class TestIMAPDiagnosticsPortOpen(unittest.TestCase):
    """Tests for IMAPDiagnostics._check_port_open()"""

    def setUp(self):
        self.config = _make_config()
        self.diag = IMAPDiagnostics(self.config)
        self.diag.logger = MagicMock()

    @patch("src.modules.imap_connection.socket.socket")
    def test_open_port_returns_true(self, mock_socket_class):
        """
        SECURITY STORY: A closed port means the IMAP server is unreachable or
        firewalled. Detecting this early avoids misleading authentication errors
        that might prompt users to rotate credentials unnecessarily.
        """
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0  # 0 == success
        mock_socket_class.return_value = mock_sock

        result = self.diag._check_port_open()

        self.assertTrue(result["open"])
        self.assertIsNone(result["error"])

    @patch("src.modules.imap_connection.socket.socket")
    def test_closed_port_returns_false(self, mock_socket_class):
        """A non-zero connect_ex return value means the port is closed."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_class.return_value = mock_sock

        result = self.diag._check_port_open()

        self.assertFalse(result["open"])


class TestIMAPDiagnosticsSSLCertificate(unittest.TestCase):
    """Tests for IMAPDiagnostics._check_ssl_certificate()"""

    def setUp(self):
        self.config = _make_config()
        self.diag = IMAPDiagnostics(self.config)
        self.diag.logger = MagicMock()

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.socket.create_connection")
    def test_valid_certificate_returns_expiry(self, mock_create_conn, mock_ssl_ctx):
        """
        SECURITY STORY: Expired or missing SSL certificates expose users to
        man-in-the-middle attacks. Valid certs must report their expiry date
        so operators can renew them before they lapse.
        """
        mock_context = MagicMock()
        mock_ssl_ctx.return_value = mock_context

        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "notAfter": "Jan 01 00:00:00 2099 GMT"
        }
        mock_context.wrap_socket.return_value.__enter__ = MagicMock(
            return_value=mock_ssock
        )
        mock_context.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        mock_raw_sock = MagicMock()
        mock_create_conn.return_value.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_create_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = self.diag._check_ssl_certificate()

        self.assertTrue(result["valid"])
        self.assertIsNotNone(result["expires_in_days"])
        self.assertIsNone(result["error"])

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.socket.create_connection")
    def test_ssl_cert_verification_error_recorded(self, mock_create_conn, mock_ssl_ctx):
        """
        SECURITY STORY: An SSLCertVerificationError indicates the server's
        certificate is invalid, expired, or self-signed. This must NOT
        be silently swallowed — it should be recorded so the operator can
        investigate a potential MITM attack.
        """
        mock_context = MagicMock()
        mock_ssl_ctx.return_value = mock_context

        mock_raw_sock = MagicMock()
        mock_create_conn.return_value.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_create_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed"
        )

        result = self.diag._check_ssl_certificate()

        self.assertFalse(result["valid"])
        self.assertIn("SSL certificate verification failed", result["error"])

    @patch("src.modules.imap_connection.create_secure_ssl_context")
    @patch("src.modules.imap_connection.socket.create_connection")
    def test_generic_ssl_error_recorded(self, mock_create_conn, mock_ssl_ctx):
        """Generic connection errors during SSL check must be caught and recorded."""
        mock_context = MagicMock()
        mock_ssl_ctx.return_value = mock_context

        mock_create_conn.side_effect = OSError("network unreachable")

        result = self.diag._check_ssl_certificate()

        self.assertFalse(result["valid"])
        self.assertIn("SSL check failed", result["error"])


if __name__ == "__main__":
    unittest.main()
