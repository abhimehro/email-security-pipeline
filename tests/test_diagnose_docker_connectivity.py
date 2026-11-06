"""
Tests for diagnose_docker_connectivity.py script.
"""

import imaplib
from unittest.mock import patch

import pytest

import diagnose_docker_connectivity

MOCK_IMAP_SECRET = "mock_value_placeholder"  # nosec B105 - test fixture only


def _disable_all_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    for prefix in ("GMAIL", "OUTLOOK", "PROTON"):
        monkeypatch.setenv(f"{prefix}_ENABLED", "false")


def test_no_accounts_enabled_warns_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Empty results trigger the setup hint and a non-zero exit."""
    _disable_all_providers(monkeypatch)

    with (
        patch("diagnose_docker_connectivity.load_dotenv"),
        pytest.raises(SystemExit) as exc_info,
    ):
        diagnose_docker_connectivity.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "No email providers enabled in .env" in captured.out


def test_outlook_configured_runs_connection_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outlook diagnostics run with the configured account when enabled."""
    _disable_all_providers(monkeypatch)
    monkeypatch.setenv("OUTLOOK_ENABLED", "true")
    monkeypatch.setenv("OUTLOOK_EMAIL", "user@outlook.com")
    monkeypatch.setenv("OUTLOOK_APP_PASSWORD", MOCK_IMAP_SECRET)
    monkeypatch.setenv("OUTLOOK_IMAP_SERVER", "outlook.office365.com")
    monkeypatch.setenv("OUTLOOK_IMAP_PORT", "993")

    with (
        patch("diagnose_docker_connectivity.load_dotenv"),
        patch.object(
            diagnose_docker_connectivity, "test_connection", return_value=True
        ) as mock_test,
        pytest.raises(SystemExit) as exc_info,
    ):
        diagnose_docker_connectivity.main()

    assert exc_info.value.code == 0
    assert mock_test.call_count == 1
    config_arg = mock_test.call_args[0][0]
    assert config_arg.label == "Outlook"
    assert config_arg.email == "user@outlook.com"
    assert config_arg.host == "outlook.office365.com"


def test_outlook_unconfigured_warns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Outlook enabled without credentials prints a configuration warning."""
    _disable_all_providers(monkeypatch)
    monkeypatch.setenv("OUTLOOK_ENABLED", "true")
    monkeypatch.setenv("OUTLOOK_EMAIL", "")
    monkeypatch.setenv("OUTLOOK_APP_PASSWORD", "")

    with (
        patch("diagnose_docker_connectivity.load_dotenv"),
        pytest.raises(SystemExit) as exc_info,
    ):
        diagnose_docker_connectivity.main()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Outlook credentials not configured" in captured.out


def test_outlook_imap_error_shows_oauth_tip(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Outlook IMAP errors explain the OAuth2 requirement and next step."""
    config = diagnose_docker_connectivity.ConnectionConfig(
        label="Outlook",
        host="outlook.office365.com",
        port=993,
        email="test@outlook.com",
        password=MOCK_IMAP_SECRET,
    )

    with patch.object(
        diagnose_docker_connectivity,
        "_create_imap_client",
        side_effect=imaplib.IMAP4.error("LOGIN failed"),
    ):
        assert diagnose_docker_connectivity.test_connection(config) is False

    out = capsys.readouterr().out
    assert "IMAP Error: LOGIN failed" in out
    assert "no longer support password authentication (OAuth2 required)" in out
    assert "OUTLOOK_TROUBLESHOOTING.md" in out


def test_non_outlook_imap_error_has_no_outlook_tip(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The Outlook tip is not shown for other providers."""
    config = diagnose_docker_connectivity.ConnectionConfig(
        label="Gmail",
        host="imap.gmail.com",
        port=993,
        email="test@gmail.com",
        password=MOCK_IMAP_SECRET,
    )

    with patch.object(
        diagnose_docker_connectivity,
        "_create_imap_client",
        side_effect=imaplib.IMAP4.error("LOGIN failed"),
    ):
        assert diagnose_docker_connectivity.test_connection(config) is False

    out = capsys.readouterr().out
    assert "IMAP Error: LOGIN failed" in out
    assert "OAuth2" not in out


def test_help_exits_zero_without_loading_env(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--help prints usage and exits 0 before any .env load or IMAP test."""
    with (
        patch("diagnose_docker_connectivity.load_dotenv") as mock_load,
        patch.object(diagnose_docker_connectivity, "test_connection") as mock_test,
        pytest.raises(SystemExit) as exc_info,
    ):
        diagnose_docker_connectivity.main(["--help"])

    assert exc_info.value.code == 0
    mock_load.assert_not_called()
    mock_test.assert_not_called()
    out = capsys.readouterr().out
    assert "usage: diagnose_docker_connectivity.py" in out
    assert "Diagnostic script to test email connectivity" in out


def test_unknown_argument_exits_with_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unknown flags fail with argparse's usage error instead of running checks."""
    with (
        patch("diagnose_docker_connectivity.load_dotenv") as mock_load,
        pytest.raises(SystemExit) as exc_info,
    ):
        diagnose_docker_connectivity.main(["--bogus"])

    assert exc_info.value.code == 2
    mock_load.assert_not_called()
    assert "unrecognized arguments: --bogus" in capsys.readouterr().err


def test_empty_argv_runs_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    """main([]) keeps the normal run path and exit status."""
    _disable_all_providers(monkeypatch)

    with (
        patch("diagnose_docker_connectivity.load_dotenv") as mock_load,
        pytest.raises(SystemExit) as exc_info,
    ):
        diagnose_docker_connectivity.main([])

    mock_load.assert_called_once_with(".env")
    assert exc_info.value.code == 1
