import unittest
from unittest.mock import patch, mock_open, call
from src.utils.setup_wizard import run_setup_wizard

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

    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.exists')
    def test_gmail_setup(self, mock_exists, mock_file, mock_getpass, mock_input):
        # Setup mocks
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = self.example_content

        # User inputs:
        # 1. Choice: '1' (Gmail)
        # 2. Email: 'myuser@gmail.com'
        # 3. Password (getpass): 'mypassword'

        mock_input.side_effect = ['1', 'myuser@gmail.com']
        mock_getpass.return_value = 'mypassword'

        # Run wizard
        result = run_setup_wizard(config_file=".env", template_file=".env.example")

        self.assertTrue(result)

        # Verify file write
        handle = mock_file()
        # The file is opened twice: once for read, once for write
        # We want to check the write call

        # Combine all written content
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)

        self.assertIn("GMAIL_ENABLED=true", written_content)
        self.assertIn("GMAIL_EMAIL=myuser@gmail.com", written_content)
        self.assertIn("GMAIL_APP_PASSWORD=mypassword", written_content)
        self.assertIn("PROTON_ENABLED=false", written_content)
        self.assertIn("OUTLOOK_ENABLED=false", written_content)

    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('builtins.open', new_callable=mock_open)
    @patch('pathlib.Path.exists')
    def test_proton_setup(self, mock_exists, mock_file, mock_getpass, mock_input):
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = self.example_content

        # Choice 2 (Proton), email, password
        mock_input.side_effect = ['2', 'myuser@pm.me']
        mock_getpass.return_value = 'protonpass'

        result = run_setup_wizard(config_file=".env", template_file=".env.example")

        self.assertTrue(result)

        handle = mock_file()
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)

        self.assertIn("PROTON_ENABLED=true", written_content)
        self.assertIn("PROTON_EMAIL=myuser@pm.me", written_content)
        self.assertIn("PROTON_APP_PASSWORD=protonpass", written_content)
        self.assertIn("GMAIL_ENABLED=false", written_content) # Should be disabled

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
