"""Independent reference implementation of FENC v1, used ONLY by the tests.

Deliberately imports nothing from fileenc: it re-implements the byte layout
with struct and the raw primitives, so engine bugs cannot hide by being
shared with the thing that checks them.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FMT = ">4sBBBBI7s16sBBB"
HSIZE = struct.calcsize(FMT)  # 38


def _aead(alg: int, key: bytes):
    return AESGCM(key) if alg == 1 else ChaCha20Poly1305(key)


def ref_header(alg, mode, klen, cs, prefix, salt=bytes(16), ln=0, r=0, p=0) -> bytes:
    return struct.pack(FMT, b"FENC", 1, alg, mode, klen, cs, prefix, salt, ln, r, p)


def ref_encrypt(plain: bytes, *, alg=1, key=None, password=None, klen=32,
                cs=1024, prefix=bytes(range(7)), salt=bytes(range(16)),
                params=(14, 8, 1)) -> bytes:
    """Deterministic encryptor: caller chooses key/prefix/salt (test use only)."""
    if password is not None:
        mode = 2
        ln, r, p = params
        key = Scrypt(salt=salt, length=klen, n=1 << ln, r=r, p=p).derive(password.encode())
    else:
        mode, salt, ln, r, p = 1, bytes(16), 0, 0, 0
    hdr = ref_header(alg, mode, klen, cs, prefix, salt, ln, r, p)
    aead = _aead(alg, key)
    n = max(1, -(-len(plain) // cs))
    out = [hdr]
    for i in range(n):
        nonce = prefix + i.to_bytes(4, "big") + (b"\x01" if i == n - 1 else b"\x00")
        out.append(aead.encrypt(nonce, plain[i * cs:(i + 1) * cs], hdr))
    return b"".join(out)


def ref_decrypt(blob: bytes, *, key=None, password=None) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on any authentication failure."""
    magic, ver, alg, mode, klen, cs, prefix, salt, ln, r, p = struct.unpack(FMT, blob[:HSIZE])
    assert magic == b"FENC" and ver == 1
    hdr = blob[:HSIZE]
    if mode == 2:
        key = Scrypt(salt=salt, length=klen, n=1 << ln, r=r, p=p).derive(password.encode())
    aead = _aead(alg, key)
    body, step = blob[HSIZE:], cs + 16
    out, off, idx = [], 0, 0
    while True:
        final = off + step >= len(body)
        nonce = prefix + idx.to_bytes(4, "big") + (b"\x01" if final else b"\x00")
        out.append(aead.decrypt(nonce, body[off:off + step], hdr))
        if final:
            return b"".join(out)
        off, idx = off + step, idx + 1
