"""Keep configuration and runtime CA path validation aligned."""

from pathlib import Path
from unittest.mock import patch

import pytest

from src.utils.config import Config, EmailAccountConfig
from src.utils.security_validators import (
    NullByteInCAPathError,
    create_secure_ssl_context,
    validate_tls_ca_path,
)


@pytest.mark.parametrize("kind", ["null", "outside", "symlink", "missing", "directory"])
def test_invalid_ca_paths_rejected_by_both_callers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.chdir(tmp_path)
    outside = tmp_path.parent / "outside-ca.pem"
    outside.write_text("fixture")
    (tmp_path / "link.pem").symlink_to(outside)
    cases = {
        "null": ("bad\0.pem", NullByteInCAPathError, "contains null bytes"),
        "outside": (str(outside), ValueError, "working tree"),
        "symlink": ("link.pem", ValueError, "working tree"),
        "missing": (
            "missing.pem",
            FileNotFoundError,
            "does not exist or is not a file",
        ),
        "directory": (".", FileNotFoundError, "does not exist or is not a file"),
    }
    ca_file, exception, message = cases[kind]
    cfg = Config.__new__(Config)
    cfg.email_accounts = [
        EmailAccountConfig(
            enabled=True,
            email="test@pm.me",
            imap_server="127.0.0.1",
            imap_port=1143,
            app_password="fixture",
            folders=["INBOX"],
            provider="proton",
            use_ssl=True,
            tls_ca_file=ca_file,
        )
    ]
    assert any(message in error for error in cfg._validate_email_accounts())
    with pytest.raises(exception):
        create_secure_ssl_context(ca_file=ca_file)


@pytest.mark.parametrize("absolute", [False, True])
def test_valid_ca_path_is_resolved_and_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, absolute: bool
) -> None:
    monkeypatch.chdir(tmp_path)
    cert = tmp_path / "ca.pem"
    cert.write_text("fixture")
    ca_file = str(cert) if absolute else cert.name
    assert validate_tls_ca_path(ca_file) == cert
    with patch("ssl.SSLContext.load_verify_locations") as load:
        create_secure_ssl_context(ca_file=ca_file)
    load.assert_called_once_with(cafile=str(cert))
