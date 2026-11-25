"""
Thin helpers for encrypting/decrypting short secrets stored in org_settings.
Delegates to the existing AES-256-GCM crypto module with a dedicated purpose tag.
"""
from app.core.crypto import decrypt, encrypt

_PURPOSE = "org_settings"


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext API key for storage in org_settings."""
    return encrypt(plaintext.encode("utf-8"), purpose=_PURPOSE)


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a ciphertext produced by encrypt_secret()."""
    return decrypt(ciphertext, purpose=_PURPOSE).decode("utf-8")
