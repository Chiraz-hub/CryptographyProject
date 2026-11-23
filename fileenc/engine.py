"""Chunked authenticated encryption (STREAM-style) for the FENC format."""
from __future__ import annotations

import os
import secrets
import tempfile
from typing import BinaryIO, Callable, Optional, TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (AESGCM,
                                                         ChaCha20Poly1305)

from . import kdf
from .errors import AuthenticationError, ParameterError
from .header import (DEFAULT_CHUNK_SIZE, DEFAULT_SCRYPT, HEADER_SIZE,
                     NONCE_PREFIX_LEN, SALT_LEN, Algorithm, Header, KeyMode)

MAX_CHUNKS = 2**32  # the nonce carries a 4-byte chunk counter
TAG_LEN = 16  # both AES-GCM and ChaCha20-Poly1305 append a 16-byte tag
GENERIC_AUTH_MSG = "wrong key or password, or the file is corrupted"
T = TypeVar("T")


def make_aead(algorithm: Algorithm, key: bytes):
    """Return the AEAD cipher object. Shared with decryption."""
    if len(key) not in algorithm.valid_key_lengths:
        raise ParameterError("key length not valid for this algorithm")
    if algorithm is Algorithm.AES_GCM:
        return AESGCM(key)
    return ChaCha20Poly1305(key)


def chunk_nonce(prefix: bytes, index: int, is_final: bool) -> bytes:
    """12-byte nonce = 7-byte file prefix | 4-byte counter | 1-byte final flag."""
    if index >= MAX_CHUNKS:
        raise ParameterError("file too large for this format")
    return prefix + index.to_bytes(4, "big") + (b"\x01" if is_final else b"\x00")


def _read_exact(src: BinaryIO, n: int) -> bytes:
    """Read up to n bytes, looping so a short read never means 'EOF'."""
    parts, remaining = [], n
    while remaining:
        block = src.read(remaining)
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


def encrypt_stream(src: BinaryIO, dst: BinaryIO, *,
                   algorithm: Algorithm = Algorithm.AES_GCM,
                   key_size: int = 32,
                   password: Optional[str] = None,
                   chunk_size: int = DEFAULT_CHUNK_SIZE) -> Optional[bytes]:
    """Encrypt `src` into `dst` in the FENC v1 format.

    Password mode (password given): the key comes from scrypt + a fresh salt.
    Raw-key mode (password None): a fresh random key is generated and
    RETURNED. It is never written to `dst`; the caller must hand it to the
    user. Returns None in password mode.
    """
    algorithm = _coerce_algorithm(algorithm)
    if key_size not in algorithm.valid_key_lengths:
        raise ParameterError(
            f"{algorithm.name} supports key sizes (bytes): "
            f"{algorithm.valid_key_lengths}")

    prefix = secrets.token_bytes(NONCE_PREFIX_LEN)
    returned_key: Optional[bytes] = None
    if password is not None:
        kdf.validate_password(password)
        salt = secrets.token_bytes(SALT_LEN)
        log2n, r, p = DEFAULT_SCRYPT
        header = Header(algorithm, KeyMode.PASSWORD, key_size, chunk_size,
                        prefix, salt, log2n, r, p)
        header_bytes = header.pack()  # validates everything first
        key = kdf.derive_key(password, salt, log2n, r, p, key_size)
    else:
        header = Header(algorithm, KeyMode.RAW, key_size, chunk_size,
                        prefix, bytes(SALT_LEN))
        header_bytes = header.pack()
        key = returned_key = kdf.generate_key(key_size)

    aead = make_aead(algorithm, key)
    dst.write(header_bytes)

    # Read one chunk ahead so we know which chunk is last BEFORE encrypting
    # it (the final flag is part of the nonce). An empty input yields one
    # empty final chunk, so even an empty file is tamper-evident.
    index = 0
    current = _read_exact(src, chunk_size)
    while True:
        upcoming = _read_exact(src, chunk_size) if len(current) == chunk_size else b""
        is_final = not upcoming
        nonce = chunk_nonce(prefix, index, is_final)
        dst.write(aead.encrypt(nonce, current, header_bytes))  # header = AAD
        if is_final:
            break
        current, index = upcoming, index + 1
    return returned_key


def atomic_write(dst_path: str, writer: Callable[[BinaryIO], T], *,
                 overwrite: bool = False) -> T:
    """Run `writer(fileobj)` into a temp file, then atomically rename to dst_path.

    The destination only ever appears COMPLETE: if `writer` raises (including
    AuthenticationError midway through a decryption), the temp file is
    deleted and dst_path is never created or modified. Refuses to replace an
    existing file unless overwrite=True.
    """
    if os.path.exists(dst_path) and not overwrite:
        raise FileExistsError(dst_path)
    dst_dir = os.path.dirname(os.path.abspath(dst_path))
    fd, tmp_path = tempfile.mkstemp(dir=dst_dir, prefix=".fenc-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            result = writer(out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_path, dst_path)  # atomic on the same filesystem
        return result
    except BaseException:
        try:
            os.unlink(tmp_path)  # note: deletion is NOT secure erasure
        except FileNotFoundError:
            pass
        raise


def encrypt_file(src_path: str, dst_path: str, *, overwrite: bool = False,
                 **kwargs) -> Optional[bytes]:
    """File-to-file encryption. Never modifies the source or a partial dst."""
    if os.path.abspath(src_path) == os.path.abspath(dst_path):
        raise ParameterError("destination must differ from source")

    def _write(out: BinaryIO) -> Optional[bytes]:
        with open(src_path, "rb") as src:
            return encrypt_stream(src, out, **kwargs)

    return atomic_write(dst_path, _write, overwrite=overwrite)


def decrypt_stream(src: BinaryIO, dst: BinaryIO, *,
                   key: Optional[bytes] = None,
                   password: Optional[str] = None) -> None:
    """Decrypt a FENC v1 stream from `src` into `dst`.

    The algorithm and all parameters come from the validated HEADER, never
    from the caller. The header also says whether a raw key or a password is
    needed; the other argument is ignored.

    WARNING: chunks are written to `dst` as each one authenticates, so `dst`
    must be treated as UNTRUSTED until this function returns normally (the
    final chunk is what proves nothing was truncated). Use decrypt_file() or
    atomic_write() so a failed run never leaves a visible output.
    """
    header_bytes = _read_exact(src, HEADER_SIZE)
    header = Header.parse(header_bytes)  # FormatError on anything off

    if header.key_mode is KeyMode.PASSWORD:
        if password is None:
            raise ParameterError("this file was encrypted with a password")
        key = kdf.derive_key(password, header.salt, header.scrypt_log2n,
                             header.scrypt_r, header.scrypt_p, header.key_length)
    else:
        if key is None:
            raise ParameterError("this file was encrypted with a raw key")
        if len(key) != header.key_length:
            raise ParameterError(
                f"wrong key length: this file needs {header.key_length} bytes "
                f"({header.key_length * 2} hex characters)")

    aead = make_aead(header.algorithm, key)
    step = header.chunk_size + TAG_LEN

    index = 0
    current = _read_exact(src, step)
    while True:
        # Same read-ahead as encryption: a chunk is final iff nothing follows.
        upcoming = _read_exact(src, step) if len(current) == step else b""
        is_final = not upcoming
        if len(current) < TAG_LEN:
            raise AuthenticationError(GENERIC_AUTH_MSG)  # truncated
        nonce = chunk_nonce(header.nonce_prefix, index, is_final)
        try:
            plaintext = aead.decrypt(nonce, current, header_bytes)
        except InvalidTag:
            raise AuthenticationError(GENERIC_AUTH_MSG) from None
        dst.write(plaintext)
        if is_final:
            return
        current, index = upcoming, index + 1


def decrypt_file(src_path: str, dst_path: str, *, overwrite: bool = False,
                 key: Optional[bytes] = None,
                 password: Optional[str] = None) -> None:
    """File-to-file decryption; dst_path appears only after full authentication."""
    if os.path.abspath(src_path) == os.path.abspath(dst_path):
        raise ParameterError("destination must differ from source")

    def _write(out: BinaryIO) -> None:
        with open(src_path, "rb") as src:
            decrypt_stream(src, out, key=key, password=password)

    atomic_write(dst_path, _write, overwrite=overwrite)


def _coerce_algorithm(value) -> Algorithm:
    try:
        return Algorithm(value)
    except ValueError:
        raise ParameterError("unsupported algorithm") from None
