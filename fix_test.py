import re

with open("tests/test_email_ingestion_manager.py", "r") as f:
    content = f.read()

# Revert the test_connection_failure_skips_remaining_folders to expect standard mock call behaviors
# It should check that result is [] and fetch_unseen_emails is not called.
old_test = '''    @patch("src.modules.email_ingestion.IMAPClient")
    def test_connection_failure_skips_remaining_folders(self, MockIMAPClient):
        """If reconnection fails, the folders simply return empty lists."""
        account = _make_account("u@x.com", folders=["INBOX", "Spam", "Archive"])

        mock_client = MagicMock()
        mock_client.ensure_connection.return_value = False

        # New temp clients for concurrent folders also fail to connect
        temp_client = MagicMock()
        temp_client.connect.return_value = False
        MockIMAPClient.return_value = temp_client

        manager = EmailIngestionManager([account])
        manager.logger = MagicMock()
        manager.clients = {"u@x.com": mock_client}

        result = manager.fetch_all_emails()

        self.assertEqual(result, [])
        mock_client.fetch_unseen_emails.assert_not_called()
        temp_client.fetch_unseen_emails.assert_not_called()'''

new_test = '''    @patch("src.modules.email_ingestion.IMAPClient")
    def test_connection_failure_skips_remaining_folders(self, MockIMAPClient):
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
        MockIMAPClient.assert_not_called()'''

if old_test in content:
    content = content.replace(old_test, new_test)
    with open("tests/test_email_ingestion_manager.py", "w") as f:
        f.write(content)
    print("Fixed test_connection_failure_skips_remaining_folders.")
else:
    print("Could not find test function to fix.")
