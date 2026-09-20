"""
Tests for diagnose_docker_connectivity.py script.
"""

import imaplib
import sys
from unittest.mock import MagicMock, patch

import pytest

import diagnose_docker_connectivity


def test_diagnose_docker_connectivity_no_accounts_enabled(monkeypatch, capsys):
    """Test that empty results trigger a warning and non-zero exit when no providers are enabled."""
    monkeypatch.setenv("GMAIL_ENABLED", "false")
    monkeypatch.setenv("OUTLOOK_ENABLED", "false")
    monkeypatch.setenv("PROTON_ENABLED", "false")

    with pytest.raises(SystemExit) as exc_info:
        diagnose_docker_connectivity.main()

    assert exc_info.value.code == 1

    captured = capsys.readouterr()
    assert "No email accounts were tested" in captured.out


def test_diagnose_docker_connectivity_outlook_configured(monkeypatch, capsys):
    """Test Outlook diagnostic execution when enabled and configured."""
    monkeypatch.setenv("GMAIL_ENABLED", "false")
    monkeypatch.setenv("PROTON_ENABLED", "false")
    monkeypatch.setenv("OUTLOOK_ENABLED", "true")
    monkeypatch.setenv("OUTLOOK_EMAIL", "user@outlook.com")
    monkeypatch.setenv("OUTLOOK_APP_PASSWORD", "secret123")
    monkeypatch.setenv("OUTLOOK_IMAP_SERVER", "outlook.office365.com")
    monkeypatch.setenv("OUTLOOK_IMAP_PORT", "993")

    with patch.object(
        diagnose_docker_connectivity, "test_connection", return_value=True
    ) as mock_test:
        with pytest.raises(SystemExit) as exc_info:
            diagnose_docker_connectivity.main()

        assert exc_info.value.code == 0
        assert mock_test.call_count == 1
        config_arg = mock_test.call_args[0][0]
        assert config_arg.label == "Outlook"
        assert config_arg.email == "user@outlook.com"
        assert config_arg.host == "outlook.office365.com"


def test_diagnose_docker_connectivity_outlook_unconfigured(monkeypatch, capsys):
    """Test Outlook warning when enabled but email/password are missing."""
    monkeypatch.setenv("GMAIL_ENABLED", "false")
    monkeypatch.setenv("PROTON_ENABLED", "false")
    monkeypatch.setenv("OUTLOOK_ENABLED", "true")
    monkeypatch.setenv("OUTLOOK_EMAIL", "")
    monkeypatch.setenv("OUTLOOK_APP_PASSWORD", "")

    with pytest.raises(SystemExit) as exc_info:
        diagnose_docker_connectivity.main()

    assert exc_info.value.code == 1

    captured = capsys.readouterr()
    assert "Outlook credentials not configured" in captured.out


def test_outlook_imap_error_shows_tip(capsys):
    """Test that Outlook IMAP errors display the helpful personal account tip."""
    config = diagnose_docker_connectivity.ConnectionConfig(
        label="Outlook",
        host="outlook.office365.com",
        port=993,
        email="test@outlook.com",
        password="badpass",
    )

    with patch.object(
        diagnose_docker_connectivity,
        "_create_imap_client",
        side_effect=imaplib.IMAP4.error("LOGIN failed"),
    ):
        result = diagnose_docker_connectivity.test_connection(config)
        assert result is False

    captured = capsys.readouterr()
    assert "Tip: Personal Outlook accounts NO LONGER support App Passwords." in captured.out
