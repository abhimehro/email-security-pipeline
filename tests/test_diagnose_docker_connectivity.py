import sys
import pytest
import diagnose_docker_connectivity

def test_diagnose_docker_connectivity_no_accounts(monkeypatch, capsys):
    monkeypatch.setenv("GMAIL_ENABLED", "false")
    monkeypatch.setenv("PROTON_ENABLED", "false")
    with pytest.raises(SystemExit) as exc_info:
        diagnose_docker_connectivity.main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "No email providers enabled in .env" in captured.out
