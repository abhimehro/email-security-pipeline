import os
import unittest
from unittest.mock import MagicMock, mock_open, patch

from src.utils.setup_wizard import (
    _generate_config_content,
    _is_valid_email,
    main,
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

    def _setup_full_mock_dependencies(self):
        patcher_exists = patch("pathlib.Path.exists", return_value=True)
        patcher_open = patch(
            "builtins.open", new_callable=mock_open, read_data=self.example_content
        )
        patcher_os_open = patch("os.open", return_value=123)
        patcher_os_fchmod = patch("os.fchmod", create=True)

        mock_write_handle = MagicMock()
        patcher_os_fdopen = patch("os.fdopen")

        patcher_getpass = patch("getpass.getpass")
        patcher_input = patch("builtins.input")
        patcher_imap_conn = patch("src.utils.setup_wizard.IMAPConnection")

        # Start all patchers
        mock_exists = patcher_exists.start()
        mock_read_file = patcher_open.start()
        mock_os_open = patcher_os_open.start()
        mock_os_fchmod = patcher_os_fchmod.start()
        mock_os_fdopen = patcher_os_fdopen.start()

        mock_getpass = patcher_getpass.start()
        mock_input = patcher_input.start()
        mock_imap_conn = patcher_imap_conn.start()

        mock_os_fdopen.return_value.__enter__.return_value = mock_write_handle

        # Add cleanups
        self.addCleanup(patcher_exists.stop)
        self.addCleanup(patcher_open.stop)
        self.addCleanup(patcher_os_open.stop)
        self.addCleanup(patcher_os_fchmod.stop)
        self.addCleanup(patcher_os_fdopen.stop)
        self.addCleanup(patcher_getpass.stop)
        self.addCleanup(patcher_input.stop)
        self.addCleanup(patcher_imap_conn.stop)

        return (
            mock_exists,
            mock_read_file,
            mock_os_open,
            mock_os_fchmod,
            mock_os_fdopen,
            mock_write_handle,
            mock_getpass,
            mock_input,
            mock_imap_conn,
        )

    def test_gmail_setup(self):
        mocks = self._setup_full_mock_dependencies()
        (
            _,
            _,
            mock_os_open,
            _,
            _,
            mock_write_handle,
            mock_getpass,
            mock_input,
            mock_imap_conn,
        ) = mocks

        # Configure connection mock to succeed
        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.return_value = True

        mock_input.side_effect = ["1", "myuser@gmail.com"]
        mock_getpass.return_value = "mypassword"

        # Run wizard
        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        # Verify permissions were set

        expected_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            expected_flags |= os.O_NOFOLLOW

        mock_os_open.assert_called_with(
            os.path.abspath(".env"),
            expected_flags,
            0o600,
        )

        written_content = "".join(
            call.args[0] for call in mock_write_handle.write.call_args_list
        )
        self.assertIn("GMAIL_ENABLED=true", written_content)
        self.assertIn("GMAIL_EMAIL=myuser@gmail.com", written_content)
        self.assertIn("GMAIL_APP_PASSWORD=mypassword", written_content)
        self.assertIn("PROTON_ENABLED=false", written_content)
        self.assertIn("OUTLOOK_ENABLED=false", written_content)

    def test_proton_setup(self):
        mocks = self._setup_full_mock_dependencies()
        (
            _,
            _,
            mock_os_open,
            _,
            _,
            mock_write_handle,
            mock_getpass,
            mock_input,
            mock_imap_conn,
        ) = mocks

        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.return_value = True

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
        self.assertIn("GMAIL_ENABLED=false", written_content)

    def test_invalid_email_retry(self):
        mocks = self._setup_full_mock_dependencies()
        (
            _,
            _,
            mock_os_open,
            _,
            _,
            mock_write_handle,
            mock_getpass,
            mock_input,
            mock_imap_conn,
        ) = mocks

        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.return_value = True

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

    def test_connection_failure_retry(self):
        mocks = self._setup_full_mock_dependencies()
        _, _, _, _, _, mock_write_handle, mock_getpass, mock_input, mock_imap_conn = (
            mocks
        )

        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.side_effect = [False, True]

        mock_input.side_effect = ["1", "bad@gmail.com", "y", "good@gmail.com"]
        mock_getpass.side_effect = ["badpassword", "goodpassword"]

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        written_content = "".join(
            call.args[0] for call in mock_write_handle.write.call_args_list
        )
        self.assertIn("GMAIL_EMAIL=good@gmail.com", written_content)
        self.assertIn("GMAIL_APP_PASSWORD=goodpassword", written_content)

    @patch("builtins.print")
    def test_connection_failure_outlook_tip(self, mock_print):
        mocks = self._setup_full_mock_dependencies()
        _, _, _, _, _, _, mock_getpass, mock_input, mock_imap_conn = mocks

        mock_conn_instance = mock_imap_conn.return_value
        mock_conn_instance.connect.side_effect = [False, True]

        mock_input.side_effect = ["3", "bad@outlook.com", "y", "good@outlook.com"]
        mock_getpass.side_effect = ["badpassword", "goodpassword"]

        result = run_setup_wizard(config_file=".env", template_file=".env.example")
        self.assertTrue(result)

        from src.utils.setup_wizard import OUTLOOK_AUTH_ERROR_TIP

        found_tip = any(
            print_call.args and OUTLOOK_AUTH_ERROR_TIP in print_call.args[0]
            for print_call in mock_print.call_args_list
        )

        self.assertTrue(
            found_tip,
            "Outlook specific troubleshooting tip not printed on connection failure.",
        )

    def _is_redacted_error(self, msg: str, password: str) -> bool:
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
        mock_imap_conn.side_effect = Exception("Auth failed for mypassword_123")
        from src.utils.setup_wizard import _test_connection

        result = _test_connection("test@outlook.com", "mypassword_123", "3")
        self.assertFalse(result)

        found_redacted = False
        found_tip = False
        from src.utils.setup_wizard import OUTLOOK_AUTH_ERROR_TIP

        for call in mock_print.call_args_list:
            if call.args and isinstance(call.args[0], str):
                msg = call.args[0]
                if self._is_redacted_error(msg, "mypassword_123"):
                    found_redacted = True
                if OUTLOOK_AUTH_ERROR_TIP in msg:
                    found_tip = True

        self.assertTrue(found_redacted)
        self.assertTrue(found_tip)

    def _run_edge_case(
        self, inputs, connect_success, read_effect, write_success, expected
    ):
        with patch("pathlib.Path.exists", return_value=True), patch(
            "builtins.open"
        ) as mock_open_func, patch("os.open", return_value=123), patch(
            "os.fchmod", create=True
        ), patch(
            "os.fdopen"
        ), patch(
            "getpass.getpass", return_value="password"
        ), patch(
            "builtins.input", side_effect=inputs
        ), patch(
            "src.utils.setup_wizard.IMAPConnection"
        ) as mock_imap, patch(
            "src.utils.setup_wizard._write_config_file", return_value=write_success
        ):

            mock_imap.return_value.connect.return_value = connect_success

            if read_effect:
                mock_open_func.side_effect = read_effect
            else:
                mock_open_func.return_value.__enter__.return_value.read.return_value = (
                    self.example_content
                )

            result = run_setup_wizard(config_file=".env", template_file=".env.example")
            self.assertEqual(result, expected)

    def test_keyboard_interrupt(self):
        self._run_edge_case([KeyboardInterrupt()], True, None, True, False)

    def test_eof_error(self):
        self._run_edge_case(["1", EOFError()], True, None, True, False)

    def test_template_read_error(self):
        self._run_edge_case(
            ["1", "test@gmail.com", "y"], True, Exception("Read error"), True, False
        )

    def test_write_config_error(self):
        self._run_edge_case(["1", "test@gmail.com", "y"], True, None, False, False)

    def test_skip_verification(self):
        self._run_edge_case(["1", "test@gmail.com", "n"], False, None, True, True)


class TestSetupWizardCLI(unittest.TestCase):
    """Smoke tests for the setup_wizard CLI entry point."""

    @patch("src.utils.setup_wizard.sys.stdin.isatty", return_value=False)
    def test_main_requires_tty(self, _mock_isatty):
        """CLI should fail immediately without a TTY."""
        self.assertEqual(main(), 1)

    @patch("src.utils.setup_wizard.sys.stdin.isatty", return_value=True)
    @patch("src.utils.setup_wizard.run_setup_wizard", return_value=True)
    def test_main_success(self, _mock_wizard, _mock_isatty):
        """CLI should return 0 when the wizard succeeds."""
        self.assertEqual(main(), 0)

    @patch("src.utils.setup_wizard.sys.stdin.isatty", return_value=True)
    @patch("src.utils.setup_wizard.run_setup_wizard", return_value=False)
    def test_main_failure(self, _mock_wizard, _mock_isatty):
        """CLI should return 1 when the wizard returns False."""
        self.assertEqual(main(), 1)

    @patch("src.utils.setup_wizard.sys.stdin.isatty", return_value=True)
    @patch(
        "src.utils.setup_wizard.run_setup_wizard",
        side_effect=EOFError(),
    )
    def test_main_eof(self, _mock_wizard, _mock_isatty):
        """CLI should return 1 on unexpected EOF."""
        self.assertEqual(main(), 1)


if __name__ == "__main__":
    unittest.main()
