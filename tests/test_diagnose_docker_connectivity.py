"""Tests for diagnose_docker_connectivity script CLI flags."""

import pytest

from diagnose_docker_connectivity import main


def test_diagnose_docker_connectivity_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Diagnostic script to test email connectivity" in captured.out
