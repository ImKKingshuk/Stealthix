from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import structlog
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import keyring

    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

from stealthix.core.errors import CredentialError

logger = structlog.get_logger(__name__)

_KDF_ITERATIONS = 390_000
_REDACTED = "***REDACTED***"


@dataclass
class CredentialStore:
    secrets: dict[str, str] = field(default_factory=dict)

    def add(self, name: str, value: str) -> None:
        self.secrets[name] = value

    def get(self, name: str) -> str | None:
        return self.secrets.get(name)

    def to_dict(self, *, include_secrets: bool = True, redacted: bool = False) -> dict[str, Any]:
        if include_secrets:
            return {"secrets": dict(self.secrets)}
        if redacted:
            return {"secrets": dict.fromkeys(self.secrets, _REDACTED)}
        return {"secrets": {}}

    @staticmethod
    def from_dict(payload: dict[str, Any]) -> CredentialStore:
        store = CredentialStore()
        store.secrets = {
            str(key): str(value)
            for key, value in dict(payload.get("secrets", {})).items()
            if value and value != _REDACTED
        }
        return store

    def _get_key_from_keyring(self, path: str) -> bytes | None:
        """Try to retrieve encryption key from OS keyring."""
        if not KEYRING_AVAILABLE:
            return None
        try:
            key = keyring.get_password("stealthix", f"key:{path}")
            if key:
                return key.encode("utf-8")
        except Exception as e:
            logger.warning(f"Failed to retrieve key from keyring: {e}")
        return None

    def _store_key_in_keyring(self, path: str, key: bytes) -> None:
        """Store encryption key in OS keyring."""
        if not KEYRING_AVAILABLE:
            return
        try:
            keyring.set_password("stealthix", f"key:{path}", key.decode("utf-8"))
            logger.debug(f"Stored encryption key in keyring for {path}")
        except Exception as e:
            logger.warning(f"Failed to store key in keyring: {e}")

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

    def _payload_bytes(self) -> bytes:
        return json.dumps({"secrets": self.secrets}, sort_keys=True).encode("utf-8")

    def _load_payload_bytes(self, payload: bytes) -> None:
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError:
            secrets = {}
            for item in payload.decode("utf-8").split("|"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    secrets[k] = v
            self.secrets = secrets
            return
        self.secrets = dict(decoded.get("secrets", {}))

    def save_encrypted(self, path: str, passphrase: str | None = None) -> None:
        """Save credentials encrypted with Fernet (AES-GCM).

        Args:
            path: File path to save credentials
            passphrase: Optional passphrase. If None, tries OS keyring first.

        Raises:
            CredentialError: If encryption fails
        """
        try:
            envelope: dict[str, Any]
            if passphrase is not None:
                salt = os.urandom(16)
                key = self._derive_key(passphrase, salt)
                envelope = {
                    "version": 2,
                    "cipher": "fernet",
                    "kdf": "pbkdf2-sha256",
                    "iterations": _KDF_ITERATIONS,
                    "salt": base64.b64encode(salt).decode("ascii"),
                }
            else:
                key = self._get_key_from_keyring(path)
                if key is None:
                    if not KEYRING_AVAILABLE:
                        raise CredentialError("No passphrase provided and keyring unavailable")
                    key = Fernet.generate_key()
                    self._store_key_in_keyring(path, key)
                envelope = {
                    "version": 2,
                    "cipher": "fernet",
                    "key_source": "keyring",
                }

            fernet = Fernet(key)
            envelope["token"] = fernet.encrypt(self._payload_bytes()).decode("ascii")

            with open(path, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, indent=2, sort_keys=True)

            logger.debug(f"Saved encrypted credentials to {path}")
        except InvalidToken as e:
            raise CredentialError(f"Invalid token for encryption: {e}") from e
        except Exception as e:
            raise CredentialError(f"Failed to save encrypted credentials: {e}") from e

    def load_encrypted(self, path: str, passphrase: str | None = None) -> None:
        """Load credentials encrypted with Fernet (AES-GCM).

        Args:
            path: File path to load credentials from
            passphrase: Optional passphrase. If None, tries OS keyring first.

        Raises:
            CredentialError: If decryption fails
        """
        try:
            raw_text = open(path, encoding="utf-8").read()
            try:
                envelope = json.loads(raw_text)
            except json.JSONDecodeError:
                envelope = None

            if isinstance(envelope, dict) and int(envelope.get("version", 0)) == 2:
                token = str(envelope.get("token") or "").encode("ascii")
                if envelope.get("kdf") == "pbkdf2-sha256":
                    if passphrase is None:
                        raise CredentialError("Passphrase required for encrypted credential file")
                    salt = base64.b64decode(str(envelope.get("salt") or ""))
                    key = self._derive_key(passphrase, salt)
                else:
                    key = self._get_key_from_keyring(path)
                    if key is None:
                        raise CredentialError("Credential key not found in OS keyring")
            else:
                token = base64.b64decode(raw_text.encode("utf-8"))
                key = self._get_key_from_keyring(path)
                if key is None:
                    raise CredentialError(
                        "Legacy credential file requires the original OS keyring key; "
                        "passphrases cannot decrypt legacy files"
                    )

            payload = Fernet(key).decrypt(token)
            self._load_payload_bytes(payload)

            logger.debug(f"Loaded encrypted credentials from {path}")
        except InvalidToken as e:
            raise CredentialError(f"Invalid token - wrong passphrase or corrupted data: {e}") from e
        except Exception as e:
            raise CredentialError(f"Failed to load encrypted credentials: {e}") from e
