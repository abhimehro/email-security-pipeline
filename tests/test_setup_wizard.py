import os
import unittest
from unittest.mock import MagicMock, mock_open, patch

from src.utils.setup_wizard import (
    _generate_config_content,
    _is_valid_email,
    run_setup_wizard,
)


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

    def test_generate_config_content_replaces_secret(self):
        """Test that setup wizard correctly replaces secret using the safe regex replace."""
        template_content = self.example_content

        # Test replacing with a string that has backslashes or special chars
        provider_key = "GMAIL"
        email = "test_new@gmail.com"
        app_secret = r"new_pass_with_\_backslashes_and_\g<0>_regex_groups"

        updated_content = _generate_config_content(
            template_content, provider_key, email, app_secret
        )

        self.assertIn(f"GMAIL_APP_PASSWORD={app_secret}", updated_content)
        self.assertIn(f"GMAIL_EMAIL={email}", updated_content)
        self.assertIn("GMAIL_ENABLED=true", updated_content)
        self.assertIn("PROTON_ENABLED=false", updated_content)
        self.assertIn("OUTLOOK_ENABLED=false", updated_content)

    def test_email_validation_logic(self):
        """Test the email validation helper function directly."""
        self.assertTrue(_is_valid_email("test@example.com"))
        self.assertTrue(_is_valid_email("user.name+tag@sub.domain.co.uk"))
        self.assertFalse(_is_valid_email("invalid-email"))
        self.assertFalse(_is_valid_email("user@"))
        self.assertFalse(_is_valid_email("@domain.com"))
        self.assertFalse(_is_valid_email("user@domain"))  # Missing TLD
        self.assertFalse(_is_valid_email("user..name@domain.com"))  # Consecutive dots

    @patch("src.utils.setup_wizard.IMAPConnection")
    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("os.fdopen")
    @patch("os.fchmod", create=True)
    @patch("os.open")
    @patch("builtins.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_gmail_setup(
        self,
        mock_exists,
        mock_read_file,
        mock_os_open,
        mock_os_fchmod,
        mock_os_fdopen,
        mock_getpass,
        mock_input,
        mock_imap_conn,
    ):
        # Setup mocks
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content

        # Configure connection mock to succeed
        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.return_value = True

        # Configure os.open to return a fake file descriptor
        mock_os_open.return_value = 123

        # Configure os.fdopen to return a mock file handle for writing
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # User inputs:
        # 1. Choice: '1' (Gmail)
        # 2. Email: 'myuser@gmail.com'
        # 3. Password (getpass): 'mypassword'

        mock_input.side_effect = ["1", "myuser@gmail.com"]
        mock_getpass.return_value = "mypassword"

        # Run wizard
        result = run_setup_wizard(config_file=".env", template_file=".env.example")

        self.assertTrue(result)

        # Verify permissions were set (0o600 = 384 in decimal)
        expected_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            expected_flags |= os.O_NOFOLLOW

        mock_os_open.assert_called_with(
            os.path.abspath(".env"),
            expected_flags,
            0o600,
        )

        # Verify file write
        # Combine all written content
        written_content = "".join(
            call.args[0] for call in mock_write_handle.write.call_args_list
        )

        self.assertIn("GMAIL_ENABLED=true", written_content)
        self.assertIn("GMAIL_EMAIL=myuser@gmail.com", written_content)
        self.assertIn("GMAIL_APP_PASSWORD=mypassword", written_content)
        self.assertIn("PROTON_ENABLED=false", written_content)
        self.assertIn("OUTLOOK_ENABLED=false", written_content)

    @patch("src.utils.setup_wizard.IMAPConnection")
    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("os.fdopen")
    @patch("os.fchmod", create=True)
    @patch("os.open")
    @patch("builtins.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_proton_setup(
        self,
        mock_exists,
        mock_read_file,
        mock_os_open,
        mock_os_fchmod,
        mock_os_fdopen,
        mock_getpass,
        mock_input,
        mock_imap_conn,
    ):
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content

        # Configure connection mock to succeed
        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.return_value = True

        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # Choice 2 (Proton), email, password
        mock_input.side_effect = ["2", "myuser@pm.me"]
        mock_getpass.return_value = "protonpass"

        result = run_setup_wizard(config_file=".env", template_file=".env.example")

        self.assertTrue(result)

        written_content = "".join(
            call.args[0] for call in mock_write_handle.write.call_args_list
        )

        self.assertIn("PROTON_ENABLED=true", written_content)
        self.assertIn("PROTON_EMAIL=myuser@pm.me", written_content)
        self.assertIn("PROTON_APP_PASSWORD=protonpass", written_content)
        self.assertIn("GMAIL_ENABLED=false", written_content)  # Should be disabled

    @patch("src.utils.setup_wizard.IMAPConnection")
    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("os.fdopen")
    @patch("os.fchmod", create=True)
    @patch("os.open")
    @patch("builtins.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_invalid_email_retry(
        self,
        mock_exists,
        mock_read_file,
        mock_os_open,
        mock_os_fchmod,
        mock_os_fdopen,
        mock_getpass,
        mock_input,
        mock_imap_conn,
    ):
        """Test that the wizard rejects invalid emails and prompts again."""
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # Configure connection mock to succeed
        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.return_value = True

        # User inputs:
        # 1. Choice: '1' (Gmail)
        # 2. Email: 'invalid-email' (should prompt again)
        # 3. Email: 'also@bad' (missing TLD, prompt again)
        # 4. Email: 'valid@gmail.com' (success)
        # 5. Password: 'pass'

        mock_input.side_effect = ["1", "invalid-email", "also@bad", "valid@gmail.com"]
        mock_getpass.return_value = "pass"

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        written_content = "".join(
            call.args[0] for call in mock_write_handle.write.call_args_list
        )
        self.assertIn("GMAIL_EMAIL=valid@gmail.com", written_content)

    @patch("builtins.input")
    @patch("pathlib.Path.exists")
    def test_missing_template(self, mock_exists, mock_input):
        mock_exists.return_value = False
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertFalse(result)

    @patch("builtins.input")
    @patch("pathlib.Path.exists")
    def test_user_skip(self, mock_exists, mock_input):
        mock_exists.return_value = True
        mock_input.return_value = "4"  # Skip
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertFalse(result)

    @patch("src.utils.setup_wizard.IMAPConnection")
    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("os.fdopen")
    @patch("os.fchmod", create=True)
    @patch("os.open")
    @patch("builtins.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_connection_failure_retry(
        self,
        mock_exists,
        mock_read_file,
        mock_os_open,
        mock_os_fchmod,
        mock_os_fdopen,
        mock_getpass,
        mock_input,
        mock_imap_conn,
    ):
        """Test that the wizard handles connection failures and allows retry."""
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # Mock connection sequence:
        # 1. Connect fails (False)
        # 2. Connect succeeds (True)
        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.side_effect = [False, True]

        # User inputs:
        # 1. Choice: '1' (Gmail)
        # 2. Email: 'bad@gmail.com'
        # 3. Password: 'badpassword'
        #    -> Connection check fails
        #    -> "Retry?" prompt: 'y'
        # 4. Email: 'good@gmail.com'
        # 5. Password: 'goodpassword'
        #    -> Connection check succeeds

        mock_input.side_effect = ["1", "bad@gmail.com", "y", "good@gmail.com"]
        mock_getpass.side_effect = ["badpassword", "goodpassword"]

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        # Verify correct credentials were used
        written_content = "".join(
            call.args[0] for call in mock_write_handle.write.call_args_list
        )
        self.assertIn("GMAIL_EMAIL=good@gmail.com", written_content)
        self.assertIn("GMAIL_APP_PASSWORD=goodpassword", written_content)

    @patch("builtins.print")
    @patch("src.utils.setup_wizard.IMAPConnection")
    @patch("builtins.input")
    @patch("getpass.getpass")
    @patch("os.fdopen")
    @patch("os.fchmod", create=True)
    @patch("os.open")
    @patch("builtins.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_connection_failure_outlook_tip(
        self,
        mock_exists,
        mock_read_file,
        mock_os_open,
        mock_os_fchmod,
        mock_os_fdopen,
        mock_getpass,
        mock_input,
        mock_imap_conn,
        mock_print,
    ):
        """Test that the wizard provides specific troubleshooting tips for Outlook on connection failure."""
        mock_exists.return_value = True
        mock_read_file.return_value.read.return_value = self.example_content
        mock_os_open.return_value = 123
        mock_write_handle = MagicMock()
        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.side_effect = [False, True]

        # 1. Choice: '3' (Outlook)
        mock_input.side_effect = ["3", "bad@outlook.com", "y", "good@outlook.com"]
        mock_getpass.side_effect = ["badpassword", "goodpassword"]

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        # Ensure the tip was printed during the first failure
        from src.utils.setup_wizard import OUTLOOK_AUTH_ERROR_TIP

        expected_tip = OUTLOOK_AUTH_ERROR_TIP

        # Check if the tip string is in any of the print calls
        found_tip = any(
            print_call.args and expected_tip in print_call.args[0]
            for print_call in mock_print.call_args_list
        )

        self.assertTrue(
            found_tip,
            "Outlook specific troubleshooting tip not printed on connection failure.",
        )

    def _is_redacted_error(self, msg: str, password: str) -> bool:
        """Check if error message is properly redacted and safe."""
        if "Error during connection test" not in msg:
            return False
        if "***" not in msg:
            return False
        if password in msg:
            return False
        return True

    @patch("builtins.print")
    @patch("src.utils.setup_wizard.IMAPConnection")
    def test_connection_test_exception(self, mock_imap_conn, mock_print):
        """Test that an exception during connection testing is caught, redacted, and prints Outlook tip."""
        # Setup IMAPConnection to raise an exception
        mock_imap_conn.side_effect = Exception("Auth failed for mypassword_123")

        # Call _test_connection directly
        from src.utils.setup_wizard import _test_connection

        result = _test_connection("test@outlook.com", "mypassword_123", "3")

        # Verify it returns False
        self.assertFalse(result)

        # Check that the exception message was printed and redacted
        found_redacted = False
        found_tip = False

        from src.utils.setup_wizard import OUTLOOK_AUTH_ERROR_TIP

        expected_tip = OUTLOOK_AUTH_ERROR_TIP

        for call in mock_print.call_args_list:
            if call.args and isinstance(call.args[0], str):
                msg = call.args[0]
                if self._is_redacted_error(msg, "mypassword_123"):
                    found_redacted = True
                if expected_tip in msg:
                    found_tip = True

        self.assertTrue(
            found_redacted, "Error message should be printed and password redacted."
        )
        self.assertTrue(
            found_tip, "Outlook specific troubleshooting tip not printed on exception."
        )

    @patch("builtins.input")
    @patch("pathlib.Path.exists")
    def test_keyboard_interrupt(self, mock_exists, mock_input):
        mock_exists.return_value = True
        mock_input.side_effect = KeyboardInterrupt()
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertFalse(result)

    @patch("builtins.input")
    @patch("pathlib.Path.exists")
    def test_eof_error(self, mock_exists, mock_input):
        mock_exists.return_value = True
        mock_input.side_effect = ["1", EOFError()]
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertFalse(result)

    def _run_wizard_with_mocks(
        self,
        inputs,
        connect_success=True,
        write_success=True,
        open_side_effect=None,
    ):
        mock_open_func = mock_open(read_data="template")
        if open_side_effect:
            mock_open_func.side_effect = open_side_effect

        with patch("src.utils.setup_wizard.IMAPConnection") as mock_imap_conn, \
             patch("pathlib.Path.exists", return_value=True), \
             patch("getpass.getpass", return_value="password"), \
             patch("builtins.input", side_effect=inputs), \
             patch("src.utils.setup_wizard._write_config_file", return_value=write_success), \
             patch("builtins.open", mock_open_func):

            mock_conn_instance = mock_imap_conn.return_value
            mock_conn_instance.connect.return_value = connect_success

            return run_setup_wizard(config_file=".env", template_file=".env.example")

    def test_template_read_error(self):
        result = self._run_wizard_with_mocks(
            inputs=["1", "test@gmail.com"],
            connect_success=True,
            open_side_effect=Exception("Read error"),
        )
        self.assertFalse(result)

    def test_write_config_error(self):
        result = self._run_wizard_with_mocks(
            inputs=["1", "test@gmail.com"],
            connect_success=True,
            write_success=False,
        )
        self.assertFalse(result)

    def test_skip_verification(self):
        result = self._run_wizard_with_mocks(
            inputs=["1", "test@gmail.com", "n"],
            connect_success=False,
            write_success=True,
        )
        self.assertTrue(result)

    def test_missing_credentials(self):
        result = self._run_wizard_with_mocks(
            inputs=["1", EOFError()],
            connect_success=False,
            write_success=True,
        )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
