import sys
import signal
from unittest.mock import patch, MagicMock
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

    with patch.object(mock_app_runner, "_handle_missing_config_interactive") as mock_interactive, \
         patch.object(mock_app_runner, "_handle_missing_config_non_interactive") as mock_non_interactive:

        mock_app_runner.ensure_config_exists()

        mock_interactive.assert_not_called()
        mock_non_interactive.assert_not_called()


@patch("src.app_runner.Path")
@patch("sys.stdin.isatty", return_value=True)
def test_ensure_config_exists_interactive(mock_isatty, mock_path, mock_app_runner):
    # We want config_file to NOT exist, but .env.example TO exist
    def path_side_effect(arg):
        mock = MagicMock()
        if arg == ".env":
            mock.exists.return_value = False
        elif arg == ".env.example":
            mock.exists.return_value = True
        return mock

    mock_path.side_effect = path_side_effect

    with patch.object(mock_app_runner, "_handle_missing_config_interactive") as mock_interactive, \
         patch.object(mock_app_runner, "_handle_missing_config_non_interactive") as mock_non_interactive:

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

    with patch.object(mock_app_runner, "_handle_missing_config_interactive") as mock_interactive, \
         patch.object(mock_app_runner, "_handle_missing_config_non_interactive") as mock_non_interactive:

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

    mock_pipeline_class.assert_called_once_with(".env")
    mock_pipeline_instance.start.assert_called_once()
