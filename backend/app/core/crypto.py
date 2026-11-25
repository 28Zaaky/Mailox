import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

_KEY_VERSION = "v1"
_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM
_HKDF_SALT = hashlib.sha256(b"mailox-v1-hkdf-salt").digest()


def _derive_key(purpose: str) -> bytes:
    """Derive a 32-byte AES-256 key for a specific purpose via HKDF-SHA256."""
    master = settings.MASTER_ENCRYPTION_KEY.get_secret_value().encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=purpose.encode("utf-8"),
    )
    return hkdf.derive(master)


def encrypt(plaintext: bytes, purpose: str = "general") -> str:
    """
    AES-256-GCM encrypt. Returns versioned base64 string: "v1:<b64(nonce+ciphertext)>".
    The GCM tag is appended to ciphertext by cryptography.
    """
    key = _derive_key(purpose)
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    encoded = base64.b64encode(nonce + ciphertext).decode("ascii")
    return f"{_KEY_VERSION}:{encoded}"


def decrypt(versioned: str, purpose: str = "general") -> bytes:
    """Decrypt a versioned AES-256-GCM string produced by encrypt()."""
    try:
        version, encoded = versioned.split(":", 1)
    except ValueError:
        raise ValueError("Invalid ciphertext format")

    if version != _KEY_VERSION:
        raise ValueError(f"Unsupported key version: {version}")

    key = _derive_key(purpose)
    combined = base64.b64decode(encoded.encode("ascii"))

    if len(combined) < _NONCE_SIZE + 16:  # 16 = GCM tag size
        raise ValueError("Ciphertext too short")

    nonce = combined[:_NONCE_SIZE]
    ciphertext = combined[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
