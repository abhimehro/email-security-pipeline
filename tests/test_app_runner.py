import signal
from unittest.mock import MagicMock, patch

import pytest

from src.app_runner import AppRunner


@pytest.fixture
def mock_app_runner():
    with patch("sys.argv", ["main.py", ".env"]):
        runner = AppRunner()
        yield runner


@patch("src.app_runner.signal.signal")
def test_setup_signal_handlers(mock_signal, mock_app_runner):
    mock_app_runner.setup_signal_handlers()

    # Verify SIGINT and SIGTERM are registered
    assert mock_signal.call_count == 2
    mock_signal.assert_any_call(signal.SIGINT, mock_app_runner._signal_handler)
    mock_signal.assert_any_call(signal.SIGTERM, mock_app_runner._signal_handler)


def test_signal_handler_raises_keyboard_interrupt():
    with pytest.raises(KeyboardInterrupt):
        AppRunner._signal_handler(signal.SIGINT, None)


@patch("src.app_runner.Path")
def test_ensure_config_exists_when_file_present(mock_path, mock_app_runner):
    # Setup the mock so that the config file exists
    mock_path_instance = MagicMock()
    mock_path_instance.exists.return_value = True
    mock_path.return_value = mock_path_instance

    with patch.object(
        mock_app_runner, "_handle_missing_config_interactive"
    ) as mock_interactive, patch.object(
        mock_app_runner, "_handle_missing_config_non_interactive"
    ) as mock_non_interactive:

        mock_app_runner.ensure_config_exists()

        mock_interactive.assert_not_called()
        mock_non_interactive.assert_not_called()


@patch("src.app_runner.Path")
@patch("sys.stdin.isatty", return_value=True)
def test_ensure_config_exists_interactive(mock_isatty, mock_path, mock_app_runner):
    # We want config_file to NOT exist, but .env.example TO exist
    def path_side_effect(arg):
        mock = MagicMock()
        if (
            str(arg) == mock_app_runner.config_file
            or arg == mock_app_runner.config_file
        ):
            mock.exists.return_value = False
        elif arg == ".env.example":
            mock.exists.return_value = True
        return mock

    mock_path.side_effect = path_side_effect

    with patch.object(
        mock_app_runner, "_handle_missing_config_interactive"
    ) as mock_interactive, patch.object(
        mock_app_runner, "_handle_missing_config_non_interactive"
    ) as mock_non_interactive:

        mock_app_runner.ensure_config_exists()

        mock_interactive.assert_called_once()
        mock_non_interactive.assert_not_called()


@patch("src.app_runner.Path")
@patch("sys.stdin.isatty", return_value=False)
def test_ensure_config_exists_non_interactive(mock_isatty, mock_path, mock_app_runner):
    # Config does not exist, and it's not a tty
    def path_side_effect(arg):
        mock = MagicMock()
        mock.exists.return_value = False
        return mock

    mock_path.side_effect = path_side_effect

    with patch.object(
        mock_app_runner, "_handle_missing_config_interactive"
    ) as mock_interactive, patch.object(
        mock_app_runner, "_handle_missing_config_non_interactive"
    ) as mock_non_interactive:

        mock_app_runner.ensure_config_exists()

        mock_interactive.assert_not_called()
        mock_non_interactive.assert_called_once()


@patch("src.app_runner.print")
def test_handle_missing_config_non_interactive(mock_print, mock_app_runner):
    with patch("src.app_runner.Path") as mock_path:
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        with patch("sys.exit") as mock_exit:
            mock_app_runner._handle_missing_config_non_interactive()
            mock_exit.assert_called_once_with(1)
            mock_print.assert_called()


@patch("src.utils.validators.check_default_credentials")
@patch("src.app_runner.Config")
def test_validate_config_success(mock_config, mock_check, mock_app_runner):
    mock_check.return_value = []
    # Should complete without sys.exit
    with patch("sys.exit") as mock_exit:
        mock_app_runner.validate_config()
        mock_exit.assert_not_called()


@patch("src.utils.validators.check_default_credentials")
@patch("src.app_runner.Config")
def test_validate_config_failure(mock_config, mock_check, mock_app_runner):
    mock_check.return_value = ["Test error"]
    with patch("sys.exit") as mock_exit:
        mock_app_runner.validate_config()
        mock_exit.assert_called_once_with(1)


@patch("src.main.EmailSecurityPipeline")
def test_start_pipeline(mock_pipeline_class, mock_app_runner):
    mock_pipeline_instance = MagicMock()
    mock_pipeline_class.return_value = mock_pipeline_instance

    mock_app_runner.start_pipeline()

    mock_pipeline_class.assert_called_once_with(mock_app_runner.config_file)
    mock_pipeline_instance.start.assert_called_once()


@patch("os.fchmod")
def test_set_secure_permissions_primary(mock_fchmod, mock_app_runner):
    mock_app_runner._set_secure_permissions(123)
    mock_fchmod.assert_called_once_with(123, 0o600)


@patch("os.chmod")
@patch("os.fchmod")
def test_set_secure_permissions_fallback_chmod_fd(
    mock_fchmod, mock_chmod, mock_app_runner
):
    mock_fchmod.side_effect = AttributeError("fchmod not available")
    mock_app_runner._set_secure_permissions(123)
    mock_fchmod.assert_called_once_with(123, 0o600)
    mock_chmod.assert_called_once_with(123, 0o600)


def test_set_secure_permissions_fallback_chmod_path(mock_app_runner):
    with patch("os.fchmod") as mock_fchmod, patch("os.fstat") as mock_fstat, patch(
        "os.lstat"
    ) as mock_lstat, patch("os.chmod") as mock_chmod:
        import os

        mock_fchmod.side_effect = AttributeError("fchmod not available")
        mock_chmod.side_effect = [TypeError("chmod fd not supported"), None]

        mock_stat_fd = MagicMock()
        mock_stat_fd.st_ino = 1
        mock_stat_fd.st_dev = 2
        mock_fstat.return_value = mock_stat_fd

        mock_stat_path = MagicMock()
        mock_stat_path.st_ino = 1
        mock_stat_path.st_dev = 2
        mock_lstat.return_value = mock_stat_path

        # Mock the follow_symlinks support
        original_supports = os.supports_follow_symlinks
        os.supports_follow_symlinks = {os.chmod}

        try:
            mock_app_runner._set_secure_permissions(123)

            mock_fchmod.assert_called_once_with(123, 0o600)
            assert mock_chmod.call_count == 2
            assert mock_chmod.call_args_list[0] == ((123, 0o600), {})
            assert mock_chmod.call_args_list[1] == (
                (mock_app_runner.config_file, 0o600),
                {"follow_symlinks": False},
            )
        finally:
            os.supports_follow_symlinks = original_supports


def test_set_secure_permissions_toctou_detected(mock_app_runner):
    with patch("os.fchmod") as mock_fchmod, patch("os.chmod") as mock_chmod, patch(
        "os.fstat"
    ) as mock_fstat, patch("os.lstat") as mock_lstat, patch(
        "src.app_runner.sys.exit"
    ) as mock_exit:
        mock_fchmod.side_effect = AttributeError("fchmod not available")
        mock_chmod.side_effect = TypeError("chmod fd not supported")
        mock_exit.side_effect = SystemExit(1)

        mock_stat_fd = MagicMock()
        mock_stat_fd.st_ino = 1
        mock_stat_fd.st_dev = 2
        mock_fstat.return_value = mock_stat_fd

        mock_stat_path = MagicMock()
        mock_stat_path.st_ino = 3  # Different inode
        mock_stat_path.st_dev = 2
        mock_lstat.return_value = mock_stat_path

        import pytest

        with pytest.raises(SystemExit) as excinfo:
            mock_app_runner._set_secure_permissions(123)

        assert excinfo.value.code == 1
        mock_exit.assert_called_once_with(1)


def test_set_secure_permissions_oserror(mock_app_runner):
    with patch("os.fchmod") as mock_fchmod, patch("os.chmod") as mock_chmod, patch(
        "os.fstat"
    ) as mock_fstat, patch("src.app_runner.sys.exit") as mock_exit:
        mock_fchmod.side_effect = AttributeError("fchmod not available")
        mock_chmod.side_effect = TypeError("chmod fd not supported")
        mock_fstat.side_effect = OSError("Permission denied")
        mock_exit.side_effect = SystemExit(1)

        import pytest

        with pytest.raises(SystemExit) as excinfo:
            mock_app_runner._set_secure_permissions(123)

        assert excinfo.value.code == 1
        mock_exit.assert_called_once_with(1)

@pytest.fixture
def mock_io():
    with patch("builtins.input") as mock_input, \
         patch("builtins.print") as mock_print, \
         patch("src.app_runner.sys.stdout.write") as mock_write, \
         patch("src.app_runner.sys.stdout.flush") as mock_flush:
        yield mock_input, mock_print, mock_write, mock_flush


@patch("src.app_runner.Colors.ENABLED", True)
@patch("src.app_runner.Colors.BOLD", "[BOLD]")
@patch("src.app_runner.Colors.RESET", "[RESET]")
def test_styled_input_colors_enabled(mock_app_runner, mock_io):
    mock_input, mock_print, mock_write, mock_flush = mock_io
    mock_input.return_value = " test_input "
    mock_flush.reset_mock()

    result = mock_app_runner._styled_input("Prompt:")

    assert result == "test_input"
    mock_input.assert_called_once_with("Prompt:[BOLD]")
    mock_print.assert_not_called()
    mock_write.assert_called_once_with("[RESET]")
    mock_flush.assert_called_once()


@patch("src.app_runner.Colors.ENABLED", False)
@patch("src.app_runner.Colors.BOLD", "[BOLD]")
@patch("src.app_runner.Colors.RESET", "[RESET]")
def test_styled_input_colors_disabled(mock_app_runner, mock_io):
    mock_input, mock_print, mock_write, mock_flush = mock_io
    mock_input.return_value = " test_input "
    mock_flush.reset_mock()

    result = mock_app_runner._styled_input("Prompt:")

    assert result == "test_input"
    mock_input.assert_called_once_with("Prompt:")
    mock_print.assert_not_called()
    mock_write.assert_not_called()
    mock_flush.assert_not_called()


@pytest.mark.parametrize("exception", [EOFError, KeyboardInterrupt])
@patch("src.app_runner.Colors.ENABLED", True)
@patch("src.app_runner.Colors.RESET", "[RESET]")
def test_styled_input_interruptions(mock_app_runner, exception, mock_io):
    mock_input, mock_print, mock_write, mock_flush = mock_io
    mock_input.side_effect = exception
    mock_flush.reset_mock()

    with pytest.raises(KeyboardInterrupt):
        mock_app_runner._styled_input("Prompt:")

    mock_print.assert_called_once_with()
    mock_write.assert_called_once_with("[RESET]")
    mock_flush.assert_called_once()
