"""Tests for diagnose_docker_connectivity script CLI flags."""

from unittest.mock import patch

import pytest

from diagnose_docker_connectivity import main


def test_diagnose_docker_connectivity_help(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch("diagnose_docker_connectivity._test_gmail_account") as gmail_test,
        patch("diagnose_docker_connectivity._test_proton_account") as proton_test,
    ):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        gmail_test.assert_not_called()
        proton_test.assert_not_called()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Diagnostic script to test email connectivity" in captured.out
