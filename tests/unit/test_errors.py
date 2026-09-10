"""Test custom exception hierarchy."""

import pytest

from stealthix.core.errors import (
    AuthError,
    ConfigError,
    CredentialError,
    DetectionError,
    EvasionError,
    NetworkError,
    PluginError,
    ReconError,
    ScanError,
    StealthixError,
)


def test_stealthix_error_is_base_exception():
    """StealthixError should be the base exception class."""
    assert issubclass(StealthixError, Exception)


def test_scan_error_inherits_from_stealthix_error():
    """ScanError should inherit from StealthixError."""
    assert issubclass(ScanError, StealthixError)


def test_detection_error_inherits_from_scan_error():
    """DetectionError should inherit from ScanError."""
    assert issubclass(DetectionError, ScanError)


def test_auth_error_inherits_from_scan_error():
    """AuthError should inherit from ScanError."""
    assert issubclass(AuthError, ScanError)


def test_extraction_error_inherits_from_scan_error():
    """ExtractionError should inherit from ScanError."""
    from stealthix.core.errors import ExtractionError

    assert issubclass(ExtractionError, ScanError)


def test_evasion_error_inherits_from_scan_error():
    """EvasionError should inherit from ScanError."""
    assert issubclass(EvasionError, ScanError)


def test_network_error_inherits_from_scan_error():
    """NetworkError should inherit from ScanError."""
    assert issubclass(NetworkError, ScanError)


def test_config_error_inherits_from_stealthix_error():
    """ConfigError should inherit from StealthixError."""
    assert issubclass(ConfigError, StealthixError)


def test_credential_error_inherits_from_stealthix_error():
    """CredentialError should inherit from StealthixError."""
    assert issubclass(CredentialError, StealthixError)


def test_plugin_error_inherits_from_stealthix_error():
    """PluginError should inherit from StealthixError."""
    assert issubclass(PluginError, StealthixError)


def test_recon_error_inherits_from_scan_error():
    """ReconError should inherit from ScanError."""
    assert issubclass(ReconError, ScanError)


def test_exception_can_be_raised_and_caught():
    """Exceptions should be raiseable and catchable."""
    with pytest.raises(StealthixError):
        raise StealthixError("test error")

    with pytest.raises(ScanError):
        raise ScanError("scan error")

    with pytest.raises(DetectionError):
        raise DetectionError("detection error")


def test_exception_preserves_message():
    """Exception messages should be preserved."""
    msg = "test error message"
    exc = StealthixError(msg)
    assert str(exc) == msg


def test_exception_chain():
    """Exception chaining should work correctly."""
    try:
        try:
            raise ValueError("original error")
        except ValueError as e:
            raise DetectionError("wrapped error") from e
    except DetectionError as exc:
        assert str(exc) == "wrapped error"
        assert exc.__cause__ is not None
        assert isinstance(exc.__cause__, ValueError)
