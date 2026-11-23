import io

from fileenc import decrypt_stream, encrypt_stream

PASSWORD = "correct horse battery staple"  # test-only, not a real secret


def enc(data: bytes, **kw):
    """Encrypt bytes in memory. Returns (blob, raw_key_or_None)."""
    dst = io.BytesIO()
    key = encrypt_stream(io.BytesIO(data), dst, **kw)
    return dst.getvalue(), key


def dec(blob: bytes, **kw) -> bytes:
    dst = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), dst, **kw)
    return dst.getvalue()
