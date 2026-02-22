import unittest
from unittest.mock import patch, mock_open, call, MagicMock
from src.utils.setup_wizard import run_setup_wizard, _is_valid_email
import os

class TestSetupWizard(unittest.TestCase):

    def setUp(self):
        self.example_content = """
# Email Security Pipeline Configuration
GMAIL_ENABLED=false
GMAIL_EMAIL=test@gmail.com
GMAIL_APP_PASSWORD=password
PROTON_ENABLED=false
PROTON_EMAIL=test@pm.me
PROTON_APP_PASSWORD=password
OUTLOOK_ENABLED=false
OUTLOOK_EMAIL=test@outlook.com
OUTLOOK_APP_PASSWORD=password
"""

    def test_email_validation_logic(self):
        """Test the email validation helper function directly"""
        self.assertTrue(_is_valid_email("test@example.com"))
        self.assertTrue(_is_valid_email("user.name+tag@sub.domain.co.uk"))
        self.assertFalse(_is_valid_email("invalid-email"))
        self.assertFalse(_is_valid_email("user@"))
        self.assertFalse(_is_valid_email("@domain.com"))
        self.assertFalse(_is_valid_email("user@domain"))  # Missing TLD
        self.assertFalse(_is_valid_email("user..name@domain.com"))  # Consecutive dots

    @patch('src.utils.setup_wizard.IMAPConnection')
    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('os.fdopen')
    @patch('os.open')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.exists')
    def test_gmail_setup(self, mock_exists, mock_read_file, mock_os_open, mock_os_fdopen, mock_getpass, mock_input, mock_imap):
        # Setup mocks
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_imap.return_value.connect.return_value = True

        # Configure os.open to return a fake file descriptor
        mock_os_open.return_value = 123

        # Configure os.fdopen to return a mock file handle for writing
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # User inputs:
        # 1. Choice: '1' (Gmail)
        # 2. Email: 'myuser@gmail.com'
        # 3. Password (getpass): 'mypassword'

        mock_input.side_effect = ['1', 'myuser@gmail.com']
        mock_getpass.return_value = 'mypassword'

        # Run wizard
        result = run_setup_wizard(config_file=".env", template_file=".env.example")

        self.assertTrue(result)

        # Verify permissions were set (0o600 = 384 in decimal)
        mock_os_open.assert_called_with(".env", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

        # Verify file write
        # Combine all written content
        written_content = "".join(call.args[0] for call in mock_write_handle.write.call_args_list)

        self.assertIn("GMAIL_ENABLED=true", written_content)
        self.assertIn("GMAIL_EMAIL=myuser@gmail.com", written_content)
        self.assertIn("GMAIL_APP_PASSWORD=mypassword", written_content)
        self.assertIn("PROTON_ENABLED=false", written_content)
        self.assertIn("OUTLOOK_ENABLED=false", written_content)

    @patch('src.utils.setup_wizard.IMAPConnection')
    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('os.fdopen')
    @patch('os.open')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.exists')
    def test_proton_setup(self, mock_exists, mock_read_file, mock_os_open, mock_os_fdopen, mock_getpass, mock_input, mock_imap):
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_imap.return_value.connect.return_value = True

        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # Choice 2 (Proton), email, password
        mock_input.side_effect = ['2', 'myuser@pm.me']
        mock_getpass.return_value = 'protonpass'

        result = run_setup_wizard(config_file=".env", template_file=".env.example")

        self.assertTrue(result)

        written_content = "".join(call.args[0] for call in mock_write_handle.write.call_args_list)

        self.assertIn("PROTON_ENABLED=true", written_content)
        self.assertIn("PROTON_EMAIL=myuser@pm.me", written_content)
        self.assertIn("PROTON_APP_PASSWORD=protonpass", written_content)
        self.assertIn("GMAIL_ENABLED=false", written_content) # Should be disabled

    @patch('src.utils.setup_wizard.IMAPConnection')
    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('os.fdopen')
    @patch('os.open')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.exists')
    def test_invalid_email_retry(self, mock_exists, mock_read_file, mock_os_open, mock_os_fdopen, mock_getpass, mock_input, mock_imap):
        """Test that the wizard rejects invalid emails and prompts again"""
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_imap.return_value.connect.return_value = True
        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # User inputs:
        # 1. Choice: '1' (Gmail)
        # 2. Email: 'invalid-email' (should prompt again)
        # 3. Email: 'also@bad' (missing TLD, prompt again)
        # 4. Email: 'valid@gmail.com' (success)
        # 5. Password: 'pass'

        mock_input.side_effect = ['1', 'invalid-email', 'also@bad', 'valid@gmail.com']
        mock_getpass.return_value = 'pass'

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        written_content = "".join(call.args[0] for call in mock_write_handle.write.call_args_list)
        self.assertIn("GMAIL_EMAIL=valid@gmail.com", written_content)

    @patch('src.utils.setup_wizard.IMAPConnection')
    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('os.fdopen')
    @patch('os.open')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.exists')
    def test_connection_retry(self, mock_exists, mock_read_file, mock_os_open, mock_os_fdopen, mock_getpass, mock_input, mock_imap):
        """Test credential retry logic upon connection failure"""
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # Scenario:
        # 1. Select Gmail (1)
        # 2. Enter email (test@gmail.com)
        # 3. Enter password (wrongpass) -> Connection Fails
        # 4. Retry? (y)
        # 5. Enter email (test@gmail.com)
        # 6. Enter password (correctpass) -> Connection Succeeds

        mock_input.side_effect = ['1', 'test@gmail.com', 'y', 'test@gmail.com']
        mock_getpass.side_effect = ['wrongpass', 'correctpass']

        # Mock IMAP connection: first fail, then success
        mock_imap.return_value.connect.side_effect = [False, True]

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        written_content = "".join(call.args[0] for call in mock_write_handle.write.call_args_list)
        self.assertIn("GMAIL_APP_PASSWORD=correctpass", written_content)

    @patch('builtins.input')
    @patch('pathlib.Path.exists')
    def test_missing_template(self, mock_exists, mock_input):
        mock_exists.return_value = False
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertFalse(result)

    @patch('builtins.input')
    @patch('pathlib.Path.exists')
    def test_user_skip(self, mock_exists, mock_input):
        mock_exists.return_value = True
        mock_input.return_value = '4' # Skip
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
