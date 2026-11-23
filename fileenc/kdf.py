"""Key material: random keys and password-based derivation (scrypt)."""
from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import ParameterError

MIN_PASSWORD_LENGTH = 12


def generate_key(length: int) -> bytes:
    """Return `length` bytes from the OS CSPRNG."""
    return secrets.token_bytes(length)


def validate_password(password: str) -> None:
    """Enforced on ENCRYPTION only; decryption accepts whatever was used."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ParameterError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters")


def derive_key(password: str, salt: bytes, log2n: int, r: int, p: int,
               length: int) -> bytes:
    """Derive a `length`-byte key from a password with scrypt.

    Parameters must already be validated (Header.validate bounds them).
    """
    kdf = Scrypt(salt=salt, length=length, n=1 << log2n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def key_to_hex(key: bytes) -> str:
    """Human-transcribable form of a raw key. Hex is an ENCODING, not protection."""
    return key.hex()


def key_from_hex(text: str) -> bytes:
    """Parse a user-supplied hex key (spaces/newlines tolerated)."""
    cleaned = "".join(text.split())
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ParameterError("key must contain only hex characters (0-9, a-f)") from None
