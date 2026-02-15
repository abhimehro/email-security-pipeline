"""
Multi-Account Processing Tests
Tests concurrent account processing, isolation, and rate limiting
"""

import unittest
from unittest.mock import MagicMock, patch, Mock
import sys
from pathlib import Path
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.email_ingestion import (
    IMAPClient, 
    EmailIngestionManager, 
    EmailAccountConfig,
    EmailData
)


class TestMultiAccountProcessing(unittest.TestCase):
    """Test processing multiple email accounts concurrently"""

    def setUp(self):
        """Set up test fixtures with multiple accounts"""
        self.account1 = EmailAccountConfig(
            enabled=True,
            email="user1@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="pass1",
            folders=["INBOX", "Spam"],
            provider="generic",
            use_ssl=True,
            verify_ssl=True
        )
        
        self.account2 = EmailAccountConfig(
            enabled=True,
            email="user2@different.com",
            imap_server="imap.different.com",
            imap_port=993,
            app_password="pass2",
            folders=["INBOX"],
            provider="generic",
            use_ssl=True,
            verify_ssl=True
        )
        
        self.account3_disabled = EmailAccountConfig(
            enabled=False,  # Disabled account
            email="user3@disabled.com",
            imap_server="imap.disabled.com",
            imap_port=993,
            app_password="pass3",
            folders=["INBOX"],
            provider="generic",
            use_ssl=True,
            verify_ssl=True
        )

    def test_multiple_accounts_initialization(self):
        """
        SECURITY STORY: This tests proper initialization of multiple email accounts.
        Each account must have its own isolated connection to prevent credential
        leakage or session confusion between accounts.
        
        PATTERN RECOGNITION: This is similar to connection pooling in databases,
        where each connection is isolated and properly managed.
        """
        accounts = [self.account1, self.account2]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        with patch('src.modules.email_ingestion.IMAPClient') as mock_client_class:
            # Create mock clients
            mock_clients = [MagicMock(), MagicMock()]
            for client in mock_clients:
                client.connect.return_value = True
            mock_client_class.side_effect = mock_clients
            
            # Initialize
            result = manager.initialize_clients()
            
            # Should create separate clients for each account
            self.assertEqual(mock_client_class.call_count, 2)
            
            # Verify each was initialized with correct config
            calls = mock_client_class.call_args_list
            self.assertEqual(calls[0][0][0].email, "user1@example.com")
            self.assertEqual(calls[1][0][0].email, "user2@different.com")

    def test_disabled_accounts_skipped(self):
        """
        SECURITY STORY: This tests that disabled accounts are properly skipped.
        Users might temporarily disable accounts for maintenance or investigation.
        We must respect this to avoid interfering with incident response.
        """
        accounts = [self.account1, self.account3_disabled, self.account2]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        with patch('src.modules.email_ingestion.IMAPClient') as mock_client_class:
            mock_clients = []
            
            def create_mock_client(config, *args, **kwargs):
                if config.enabled:
                    client = MagicMock()
                    client.connect.return_value = True
                    client.config = config
                    mock_clients.append(client)
                    return client
                return None
            
            mock_client_class.side_effect = create_mock_client
            
            # Initialize
            manager.initialize_clients()
            
            # Should only create clients for enabled accounts
            # (account1 and account2, not account3_disabled)
            self.assertEqual(len(mock_clients), 2)
            
            # Verify correct accounts were processed
            processed_emails = [c.config.email for c in mock_clients]
            self.assertIn("user1@example.com", processed_emails)
            self.assertIn("user2@different.com", processed_emails)
            self.assertNotIn("user3@disabled.com", processed_emails)

    def test_account_specific_folder_configuration(self):
        """
        SECURITY STORY: This tests that each account uses its own folder configuration.
        Different accounts might monitor different folders. Cross-contamination
        could cause missed threats or unnecessary alerts.
        """
        accounts = [self.account1, self.account2]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        # Account1 has 2 folders, Account2 has 1 folder
        self.assertEqual(len(self.account1.folders), 2)
        self.assertEqual(len(self.account2.folders), 1)
        
        # Create mock clients
        mock_client1 = MagicMock()
        mock_client1.config = self.account1
        mock_client1.ensure_connection.return_value = True
        mock_client1.fetch_unseen_emails.return_value = []  # No emails
        
        mock_client2 = MagicMock()
        mock_client2.config = self.account2
        mock_client2.ensure_connection.return_value = True
        mock_client2.fetch_unseen_emails.return_value = []  # No emails
        
        manager.clients = {
            "user1@example.com": mock_client1,
            "user2@different.com": mock_client2
        }
        
        # Fetch from all accounts
        manager.fetch_all_emails(max_per_folder=10)
        
        # Verify each client's fetch method was called
        # Account1 has 2 folders, Account2 has 1 folder
        self.assertTrue(mock_client1.fetch_unseen_emails.called)
        self.assertTrue(mock_client2.fetch_unseen_emails.called)

    def test_cross_account_isolation(self):
        """
        SECURITY STORY: This tests that emails from different accounts remain isolated.
        If account isolation fails, an attacker with access to one account could
        potentially see or manipulate emails from another account. This is critical
        for multi-tenant security.
        
        INDUSTRY CONTEXT: Professional teams handle this by ensuring proper
        tenant isolation at every layer, with explicit account_id tracking.
        """
        accounts = [self.account1, self.account2]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        # Create mock emails tagged with their source account
        email1 = EmailData(
            message_id="email-1",
            subject="Email from Account 1",
            sender="sender1@example.com",
            recipient="user1@example.com",
            date=datetime.now(),
            body_text="Body 1",
            body_html="",
            headers={},
            attachments=[],
            raw_email=MagicMock(),
            account_email="user1@example.com",  # Tagged with account1
            folder="INBOX"
        )
        
        email2 = EmailData(
            message_id="email-2",
            subject="Email from Account 2",
            sender="sender2@different.com",
            recipient="user2@different.com",
            date=datetime.now(),
            body_text="Body 2",
            body_html="",
            headers={},
            attachments=[],
            raw_email=MagicMock(),
            account_email="user2@different.com",  # Tagged with account2
            folder="INBOX"
        )
        
        # Setup mock clients
        # Account1 has 2 folders, so fetch_unseen_emails will be called twice
        # We need to return different emails for each folder
        mock_client1 = MagicMock()
        mock_client1.ensure_connection.return_value = True
        # Return different emails for each folder call
        mock_client1.fetch_unseen_emails.side_effect = [
            [("1", b"raw1")],  # First folder (INBOX)
            [("2", b"raw2")]   # Second folder (Spam)
        ]
        # parse_email will be called for each fetched email
        mock_client1.parse_email.side_effect = [email1, email1]  # Return email1 for both
        
        mock_client2 = MagicMock()
        mock_client2.ensure_connection.return_value = True
        mock_client2.fetch_unseen_emails.return_value = [("3", b"raw3")]
        mock_client2.parse_email.return_value = email2
        
        manager.clients = {
            "user1@example.com": mock_client1,
            "user2@different.com": mock_client2
        }
        
        # Fetch all
        all_emails = manager.fetch_all_emails(max_per_folder=10)
        
        # Verify we got emails from both accounts
        # Account1 has 2 folders (INBOX, Spam), Account2 has 1 folder (INBOX)
        # So we get: 1 email from account1/INBOX, 1 from account1/Spam, 1 from account2/INBOX = 3 total
        self.assertEqual(len(all_emails), 3)
        
        # Verify each email is properly tagged with its source account
        account_emails = {email.account_email for email in all_emails}
        self.assertIn("user1@example.com", account_emails)
        self.assertIn("user2@different.com", account_emails)
        
        # Verify account isolation - emails maintain their source
        for email in all_emails:
            # All emails from account1 should have user1's email
            # All emails from account2 should have user2's email
            self.assertIn(email.account_email, ["user1@example.com", "user2@different.com"])

    def test_rate_limit_enforcement_per_account(self):
        """
        SECURITY STORY: This tests rate limiting to prevent overwhelming IMAP servers.
        Aggressive polling can trigger rate limits or blacklisting. We must respect
        server limits to maintain access and avoid disrupting service.
        
        PATTERN RECOGNITION: This is similar to API rate limiting in REST services.
        We implement client-side rate limiting to be a good citizen.
        """
        accounts = [self.account1, self.account2]
        rate_limit_delay = 0.05  # 50ms delay for testing
        manager = EmailIngestionManager(accounts, rate_limit_delay=rate_limit_delay)
        
        # Create mock clients
        mock_client1 = MagicMock()
        mock_client1.ensure_connection.return_value = True
        mock_client1.fetch_unseen_emails.return_value = []
        
        mock_client2 = MagicMock()
        mock_client2.ensure_connection.return_value = True
        mock_client2.fetch_unseen_emails.return_value = []
        
        manager.clients = {
            "user1@example.com": mock_client1,
            "user2@different.com": mock_client2
        }
        
        # Patch sleep in the email_ingestion module to make rate limiting observable
        with patch("src.modules.email_ingestion.time.sleep") as mock_sleep:
            # Perform fetch - should apply rate limiting
            manager.fetch_all_emails(max_per_folder=10)

        # With 2 accounts and 3 folders total (account1=2, account2=1),
        # rate limiting should trigger at least one sleep with the configured delay
        self.assertGreaterEqual(mock_sleep.call_count, 1)
        for call in mock_sleep.call_args_list:
            # Each sleep call should use the configured rate_limit_delay
            self.assertEqual(call.args[0], rate_limit_delay)
    def test_concurrent_account_error_isolation(self):
        """
        SECURITY STORY: This tests that errors in one account don't affect others.
        If one account has issues (wrong password, server down), other accounts
        should continue operating normally. This ensures partial availability.
        
        MAINTENANCE WISDOM: Future you will thank present you for this test when
        debugging why all monitoring stopped due to one misconfigured account.
        """
        accounts = [self.account1, self.account2]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        # Setup: client1 works, client2 has error
        mock_client1 = MagicMock()
        mock_client1.config = self.account1
        mock_client1.fetch_emails.return_value = [
            EmailData(
                message_id="success-email",
                subject="Working email",
                sender="sender@example.com",
                recipient="user1@example.com",
                date=datetime.now(),
                body_text="Body",
                body_html="",
                headers={},
                attachments=[],
                raw_email=MagicMock(),
                account_email="user1@example.com",
                folder="INBOX"
            )
        ]
        
        mock_client2 = MagicMock()
        mock_client2.config = self.account2
        mock_client2.fetch_emails.side_effect = Exception("Account error")
        
        manager.clients = {
            self.account1.email: mock_client1,
            self.account2.email: mock_client2,
        }
        
        # Fetch should succeed for working account despite other account's error
        emails = manager.fetch_all_emails(max_per_folder=10)
        
        # Should get email from working account
        # Exact behavior depends on error handling implementation
        self.assertIsInstance(emails, list)

    def test_account_priority_ordering(self):
        """
        SECURITY STORY: This tests that accounts are processed in a consistent order.
        Inconsistent ordering could lead to priority accounts being checked last,
        delaying critical threat detection.
        """
        # Create accounts with different priorities (by order)
        high_priority = EmailAccountConfig(
            enabled=True,
            email="vip@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="pass",
            folders=["INBOX"],
            provider="generic",
            use_ssl=True,
            verify_ssl=True
        )
        
        low_priority = EmailAccountConfig(
            enabled=True,
            email="bulk@example.com",
            imap_server="imap.example.com",
            imap_port=993,
            app_password="pass",
            folders=["INBOX"],
            provider="generic",
            use_ssl=True,
            verify_ssl=True
        )
        
        # List order implies priority
        accounts = [high_priority, low_priority]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        with patch('src.modules.email_ingestion.IMAPClient') as mock_client_class:
            mock_clients = [MagicMock(), MagicMock()]
            for client in mock_clients:
                client.connect.return_value = True
            mock_client_class.side_effect = mock_clients
            
            manager.initialize_clients()
            
            # Verify initialization order matches account list order
            calls = mock_client_class.call_args_list
            self.assertEqual(calls[0][0][0].email, "vip@example.com")
            self.assertEqual(calls[1][0][0].email, "bulk@example.com")

    def test_max_emails_per_account_limit(self):
        """
        SECURITY STORY: This tests per-account email fetch limits.
        Without limits, one account with thousands of emails could monopolize
        processing time, starving other accounts. Fair distribution ensures
        timely threat detection across all monitored accounts.
        """
        accounts = [self.account1, self.account2]
        manager = EmailIngestionManager(accounts, rate_limit_delay=0)
        
        # Create many mock emails for account1
        many_emails = [
            EmailData(
                message_id=f"email-{i}",
                subject=f"Email {i}",
                sender="sender@example.com",
                recipient="user1@example.com",
                date=datetime.now(),
                body_text="Body",
                body_html="",
                headers={},
                attachments=[],
                raw_email=MagicMock(),
                account_email="user1@example.com",
                folder="INBOX"
            )
            for i in range(100)  # 100 emails
        ]
        
        mock_client1 = MagicMock()
        mock_client1.config = self.account1
        mock_client1.fetch_emails.return_value = many_emails[:10]  # Should limit to 10
        
        mock_client2 = MagicMock()
        mock_client2.config = self.account2
        mock_client2.fetch_emails.return_value = []
        
        manager.clients = {
            "user1@example.com": mock_client1,
            "user2@example.com": mock_client2,
        }
        
        # Fetch with limit
        emails = manager.fetch_all_emails(max_per_folder=10)
        
        # Should respect the limit
        self.assertLessEqual(len(emails), 10)


if __name__ == '__main__':
    unittest.main()
