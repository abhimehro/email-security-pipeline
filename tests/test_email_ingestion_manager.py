"""
Unit tests for EmailIngestionManager multi-account orchestration.

PATTERN RECOGNITION: EmailIngestionManager is a Coordinator — it manages
multiple IMAPClient instances and orchestrates email fetching across accounts.
These tests verify its partial-failure semantics and boundary behaviour without
making any real network calls (all IMAP interaction is mocked).

SECURITY STORY: The partial-failure design in initialize_clients() is a
resilience pattern — if one account's credentials are stolen and the server
locks it out, the pipeline keeps running on the remaining healthy accounts
rather than going completely blind.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import EmailIngestionManager
from src.utils.config import EmailAccountConfig


def _make_account(email="user@example.com", enabled=True, folders=None):
    """Helper: create a minimal EmailAccountConfig for tests."""
    return EmailAccountConfig(
        enabled=enabled,
        email=email,
        imap_server="imap.example.com",
        imap_port=993,
        app_password="secret",
        folders=folders or ["INBOX"],
        provider="test",
        use_ssl=True,
        verify_ssl=True,
    )


class TestEmailIngestionManagerInitialize(unittest.TestCase):
    """Tests for initialize_clients()."""

    @patch("src.modules.email_ingestion.IMAPClient")
    def test_all_succeed_returns_true_and_stores_all_clients(self, MockClient):
        """All accounts connect → True; every client stored by email."""
        accounts = [_make_account("a@x.com"), _make_account("b@x.com")]
        MockClient.return_value.connect.return_value = True

        manager = EmailIngestionManager(accounts)
        manager.logger = MagicMock()

        result = manager.initialize_clients()

        self.assertTrue(result)
        self.assertEqual(len(manager.clients), 2)
        self.assertIn("a@x.com", manager.clients)
        self.assertIn("b@x.com", manager.clients)

    @patch("src.modules.email_ingestion.IMAPClient")
    def test_all_fail_returns_false_and_no_clients(self, MockClient):
        """All connections fail → False; no clients stored."""
        accounts = [_make_account("a@x.com"), _make_account("b@x.com")]
        MockClient.return_value.connect.return_value = False

        manager = EmailIngestionManager(accounts)
        manager.logger = MagicMock()

        result = manager.initialize_clients()

        self.assertFalse(result)
        self.assertEqual(len(manager.clients), 0)

    @patch("src.modules.email_ingestion.IMAPClient")
    def test_partial_failure_returns_true_with_only_successful_client(self, MockClient):
        """1-of-3 accounts succeeds → True; only the successful client stored.

        SECURITY STORY: Partial-failure semantics mean that if attacker forces
        two accounts offline, the pipeline continues monitoring with the third.
        """
        accounts = [
            _make_account("fail1@x.com"),
            _make_account("ok@x.com"),
            _make_account("fail2@x.com"),
        ]

        def _make_client(account, *args, **kwargs):
            m = MagicMock()
            m.connect.return_value = account.email == "ok@x.com"
            return m

        MockClient.side_effect = _make_client

        manager = EmailIngestionManager(accounts)
        manager.logger = MagicMock()

        result = manager.initialize_clients()

        self.assertTrue(result)
        self.assertEqual(len(manager.clients), 1)
        self.assertIn("ok@x.com", manager.clients)

    @patch("src.modules.email_ingestion.IMAPClient")
    def test_no_accounts_returns_false(self, MockClient):
        """Empty account list → False; no IMAPClient constructed."""
        manager = EmailIngestionManager([])
        manager.logger = MagicMock()

        result = manager.initialize_clients()

        self.assertFalse(result)
        MockClient.assert_not_called()

    @patch("src.modules.email_ingestion.IMAPClient")
    def test_disabled_accounts_are_skipped(self, MockClient):
        """Disabled accounts never create an IMAPClient."""
        accounts = [
            _make_account("on@x.com", enabled=True),
            _make_account("off@x.com", enabled=False),
        ]
        MockClient.return_value.connect.return_value = True

        manager = EmailIngestionManager(accounts)
        manager.logger = MagicMock()

        result = manager.initialize_clients()

        self.assertTrue(result)
        self.assertEqual(MockClient.call_count, 1)
        self.assertIn("on@x.com", manager.clients)
        self.assertNotIn("off@x.com", manager.clients)


class TestEmailIngestionManagerFetch(unittest.TestCase):
    """Tests for fetch_all_emails()."""

    def test_single_client_single_folder_returns_emails(self):
        """Happy path: one account, one folder, emails returned."""
        account = _make_account("u@x.com", folders=["INBOX"])
        mock_email = MagicMock()

        mock_client = MagicMock()
        mock_client.ensure_connection.return_value = True
        mock_client.fetch_unseen_emails.return_value = [("1", b"raw")]
        mock_client.parse_email.return_value = mock_email

        manager = EmailIngestionManager([account])
        manager.logger = MagicMock()
        manager.clients = {"u@x.com": mock_client}

        result = manager.fetch_all_emails()

        self.assertEqual(result, [mock_email])
        mock_client.fetch_unseen_emails.assert_called_once_with("INBOX", 50)

    def test_connection_failure_skips_remaining_folders(self):
        """If reconnection fails, all remaining folders for that account are skipped."""
        account = _make_account("u@x.com", folders=["INBOX", "Spam", "Archive"])

        mock_client = MagicMock()
        mock_client.ensure_connection.return_value = False

        manager = EmailIngestionManager([account])
        manager.logger = MagicMock()
        manager.clients = {"u@x.com": mock_client}

        result = manager.fetch_all_emails()

        self.assertEqual(result, [])
        mock_client.fetch_unseen_emails.assert_not_called()

    def test_parse_email_returning_none_is_excluded(self):
        """parse_email returning None (malformed/oversized mail) is excluded."""
        account = _make_account("u@x.com", folders=["INBOX"])

        mock_client = MagicMock()
        mock_client.ensure_connection.return_value = True
        mock_client.fetch_unseen_emails.return_value = [("1", b"bad")]
        mock_client.parse_email.return_value = None

        manager = EmailIngestionManager([account])
        manager.logger = MagicMock()
        manager.clients = {"u@x.com": mock_client}

        result = manager.fetch_all_emails()

        self.assertEqual(result, [])

    def test_multiple_folders_aggregated(self):
        """Emails from multiple folders are combined into a single list."""
        account = _make_account("u@x.com", folders=["INBOX", "Spam"])
        email_inbox = MagicMock()
        email_spam = MagicMock()

        mock_client = MagicMock()
        mock_client.ensure_connection.return_value = True
        mock_client.fetch_unseen_emails.side_effect = [
            [("1", b"raw1")],
            [("2", b"raw2")],
        ]
        mock_client.parse_email.side_effect = [email_inbox, email_spam]

        manager = EmailIngestionManager([account])
        manager.logger = MagicMock()
        manager.clients = {"u@x.com": mock_client}

        result = manager.fetch_all_emails()

        self.assertEqual(result, [email_inbox, email_spam])


class TestEmailIngestionManagerClose(unittest.TestCase):
    """Tests for close_all_connections()."""

    def test_all_disconnects_succeed_clears_clients(self):
        """All clients disconnected; clients dict is empty afterward."""
        mock_clients = {f"{i}@x.com": MagicMock() for i in range(3)}

        manager = EmailIngestionManager([])
        manager.logger = MagicMock()
        manager.clients = dict(mock_clients)

        manager.close_all_connections()

        for m in mock_clients.values():
            m.disconnect.assert_called_once()
        self.assertEqual(manager.clients, {})

    def test_one_disconnect_raises_others_still_called(self):
        """When one client raises on disconnect(), the others are still disconnected.

        MAINTENANCE WISDOM: Without try/except in the loop, a single flaky
        connection would prevent cleanup of all subsequent clients — a
        resource-leak waiting to happen in long-running deployments.
        """
        m1 = MagicMock()
        m2 = MagicMock()
        m3 = MagicMock()
        m2.disconnect.side_effect = Exception("connection reset")

        manager = EmailIngestionManager([])
        manager.logger = MagicMock()
        manager.clients = {"a@x.com": m1, "b@x.com": m2, "c@x.com": m3}

        # Should NOT raise — exceptions are swallowed and logged
        manager.close_all_connections()

        m1.disconnect.assert_called_once()
        m2.disconnect.assert_called_once()
        m3.disconnect.assert_called_once()
        self.assertEqual(manager.clients, {})
        manager.logger.warning.assert_called_once()


class TestEmailIngestionManagerDiagnose(unittest.TestCase):
    """Tests for diagnose_account_connection()."""

    @patch("src.modules.email_ingestion.IMAPClient")
    def test_known_account_returns_diagnostics(self, MockClient):
        """Known email address → diagnostics dict from IMAPClient."""
        account = _make_account("u@x.com")
        diag_result = {"connected": True, "latency_ms": 42}

        MockClient.return_value.diagnose_connection_issues.return_value = diag_result

        manager = EmailIngestionManager([account])
        manager.logger = MagicMock()

        result = manager.diagnose_account_connection("u@x.com")

        self.assertEqual(result, diag_result)

    def test_unknown_account_returns_none(self):
        """Unknown email address → None (account not in config)."""
        manager = EmailIngestionManager([_make_account("u@x.com")])
        manager.logger = MagicMock()

        result = manager.diagnose_account_connection("nobody@x.com")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
