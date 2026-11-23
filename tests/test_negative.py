"""Failure behaviour: every modification must be a controlled FileEncError and
must never return plaintext."""
import io
import os

import pytest

from fileenc import (Algorithm, AuthenticationError, FileEncError, FormatError,
                     ParameterError, decrypt_stream, encrypt_stream)
from fileenc.header import HEADER_SIZE
from fileenc.kdf import key_from_hex, key_to_hex

from .helpers import PASSWORD, dec, enc
from .reference import ref_encrypt

CS = 1024
STEP = CS + 16


class Leak(io.BytesIO):
    """Records anything written so tests can assert nothing was RELEASED."""


def must_fail(blob, **kw):
    with pytest.raises(FileEncError):
        dec(blob, **kw)


@pytest.fixture(scope="module")
def multi():
    data = os.urandom(3 * CS + 10)  # 4 chunks
    blob, key = enc(data, chunk_size=CS)
    return data, blob, key


@pytest.fixture(scope="module")
def single():
    data = b"short single-chunk file"
    blob, key = enc(data, chunk_size=CS)
    return data, blob, key


# ---------- wrong secrets ----------
def test_wrong_raw_key(multi):
    _, blob, key = multi
    with pytest.raises(AuthenticationError):
        dec(blob, key=bytes([key[0] ^ 1]) + key[1:])


def test_wrong_password():
    blob, _ = enc(b"data", password=PASSWORD)
    with pytest.raises(AuthenticationError):
        dec(blob, password=PASSWORD + "x")


def test_wrong_secret_type_for_file_mode(multi):
    _, blob, key = multi
    with pytest.raises(ParameterError):
        dec(blob, password=PASSWORD)           # raw-key file, only password supplied
    pblob, _ = enc(b"data", password=PASSWORD)
    with pytest.raises(ParameterError):
        dec(pblob, key=key)                    # password file, only key supplied


def test_wrong_length_key_is_a_parameter_error(multi):
    _, blob, key = multi
    for bad in (b"", key[:-1], key + b"\x00", key[:16]):
        with pytest.raises(ParameterError):
            dec(blob, key=bad)


def test_unused_secret_is_ignored_not_tried_as_fallback(multi):
    _, blob, key = multi
    assert dec(blob, key=key, password="irrelevant") == multi[0]
    pblob, _ = enc(b"abc", password=PASSWORD)
    assert dec(pblob, password=PASSWORD, key=bytes(32)) == b"abc"


def test_no_silent_fallback_to_other_algorithm():
    # AES file whose algorithm id is rewritten to ChaCha (same 32-byte key length).
    blob, key = enc(b"x" * 100, algorithm=Algorithm.AES_GCM, key_size=32, chunk_size=CS)
    forged = bytearray(blob); forged[5] = 2
    with pytest.raises(AuthenticationError):
        dec(bytes(forged), key=key)


# ---------- exhaustive single-bit flips ----------
@pytest.mark.parametrize("bit", [0x01, 0x80])
def test_flip_every_header_byte_raw_mode_single_chunk(single, bit):
    """Single-chunk file: the chunk-size field is only protected by the AAD, so this
    is the test that proves the header really is authenticated."""
    data, blob, key = single
    for off in range(HEADER_SIZE):
        f = bytearray(blob); f[off] ^= bit
        with pytest.raises(FileEncError):
            dec(bytes(f), key=key)


def test_flip_every_header_byte_password_mode():
    blob, _ = enc(b"password mode data", password=PASSWORD, chunk_size=CS)
    for off in range(HEADER_SIZE):
        f = bytearray(blob); f[off] ^= 0x01
        with pytest.raises(FileEncError):
            dec(bytes(f), password=PASSWORD)


def test_flip_every_ciphertext_and_tag_byte(multi):
    _, blob, key = multi
    for off in range(HEADER_SIZE, len(blob)):
        f = bytearray(blob); f[off] ^= 0x01
        with pytest.raises(AuthenticationError):
            dec(bytes(f), key=key)


# ---------- truncation / extension at every length ----------
def test_every_truncation_length_is_detected(multi):
    _, blob, key = multi
    for n in range(len(blob)):             # 0 .. len-1: includes exact chunk boundaries
        with pytest.raises(FileEncError):
            dec(blob[:n], key=key)


def test_truncation_at_chunk_boundary_is_authentication_failure_not_success(multi):
    data, blob, key = multi
    for k in (1, 2, 3):
        cut = blob[:HEADER_SIZE + k * STEP]
        with pytest.raises(AuthenticationError):
            dec(cut, key=key)


def test_empty_file_ciphertext_truncated_to_header_only():
    blob, key = enc(b"", chunk_size=CS)
    assert len(blob) == HEADER_SIZE + 16
    must_fail(blob[:HEADER_SIZE], key=key)
    must_fail(blob[:HEADER_SIZE + 8], key=key)


def test_appending_any_amount_of_data_is_detected(multi):
    _, blob, key = multi
    for n in range(1, 60):
        must_fail(blob + b"\x00" * n, key=key)
    must_fail(blob + blob[HEADER_SIZE:HEADER_SIZE + STEP], key=key)   # appended valid-looking chunk


# ---------- reorder / duplicate / drop / splice ----------
def _chunks(blob):
    body = blob[HEADER_SIZE:]
    return [body[i:i + STEP] for i in range(0, len(body), STEP)]


def test_reordered_duplicated_dropped_chunks(multi):
    _, blob, key = multi
    h, c = blob[:HEADER_SIZE], _chunks(blob)
    assert len(c) == 4
    must_fail(h + c[1] + c[0] + c[2] + c[3], key=key)      # swap first two
    must_fail(h + c[0] + c[1] + c[3] + c[2], key=key)      # swap last two (final chunk moved)
    must_fail(h + c[0] + c[0] + c[1] + c[2] + c[3], key=key)  # duplicate
    must_fail(h + c[0] + c[2] + c[3], key=key)             # drop a middle chunk
    must_fail(h + c[1] + c[2] + c[3], key=key)             # drop the first chunk
    must_fail(h + c[0] + c[1] + c[2] + c[2], key=key)      # replace final with a non-final


def test_chunk_spliced_from_another_file_with_same_key():
    key = os.urandom(32)
    a = ref_encrypt(os.urandom(3 * CS), key=key, cs=CS, prefix=b"A" * 7)
    b = ref_encrypt(os.urandom(3 * CS), key=key, cs=CS, prefix=b"B" * 7)
    ca, cb = _chunks(a), _chunks(b)
    must_fail(a[:HEADER_SIZE] + ca[0] + cb[1] + ca[2], key=key)


def test_nothing_is_released_when_final_chunk_is_missing(multi):
    """decrypt_stream may emit early chunks (documented), but atomic callers never
    expose them; this pins the documented behaviour so nobody 'optimises' it away."""
    data, blob, key = multi
    sink = Leak()
    with pytest.raises(AuthenticationError):
        decrypt_stream(io.BytesIO(blob[:HEADER_SIZE + 3 * STEP]), sink, key=key)
    # Chunks 0 and 1 were followed by more data, so they authenticated and were written
    # to the (untrusted) sink. Chunk 2 was last-in-file, so it was checked as FINAL
    # (flag=1), failed, and was never written: the truncated tail is never released.
    assert sink.getvalue() == data[:2 * CS]
    # ...which is exactly why decrypt_file/atomic_write exist: see tests/test_files.py


# ---------- malformed / unsupported ----------
@pytest.mark.parametrize("blob", [b"", b"FENC", b"not an encrypted file at all" * 5,
                                  bytes(100), b"\xff" * 100, b"FENC" + bytes(34)])
def test_garbage_input_is_format_error(blob):
    with pytest.raises(FormatError):
        dec(blob, key=bytes(32))


def test_old_legacy_style_headerless_ciphertext_is_rejected_cleanly():
    """Compatibility decision (Phase 2): pre-v1 files (raw CBC bytes + loose .key/.iv)
    carry no header, so they are rejected with FormatError, never mis-decrypted."""
    legacy_like = os.urandom(256)              # what an old *.enc looked like: raw bytes
    with pytest.raises(FormatError):
        dec(legacy_like, key=os.urandom(32))


# ---------- parameter validation on encryption ----------
@pytest.mark.parametrize("kw", [
    dict(algorithm=99), dict(algorithm="aes"), dict(algorithm=None), dict(algorithm=0),
    dict(key_size=0), dict(key_size=15), dict(key_size=20), dict(key_size=33), dict(key_size=-1),
    dict(algorithm=Algorithm.CHACHA20_POLY1305, key_size=16),
    dict(algorithm=Algorithm.CHACHA20_POLY1305, key_size=24),
    dict(chunk_size=0), dict(chunk_size=1), dict(chunk_size=1023), dict(chunk_size=16 * 1024 * 1024 + 1),
    dict(password=""), dict(password="short"), dict(password="elevenchars"), dict(password=12345678901234),
])
def test_invalid_encryption_parameters_rejected(kw):
    out = io.BytesIO()
    with pytest.raises(ParameterError):
        encrypt_stream(io.BytesIO(b"x"), out, **kw)
    assert out.getvalue() == b""               # rejected BEFORE anything was written


def test_twelve_character_password_is_the_minimum():
    blob, _ = enc(b"x", password="twelve chars")
    assert dec(blob, password="twelve chars") == b"x"


# ---------- hex key helpers ----------
def test_key_hex_roundtrip_and_tolerance():
    k = os.urandom(32)
    h = key_to_hex(k)
    assert key_from_hex(h) == k == key_from_hex(h.upper())
    assert key_from_hex(" ".join(h[i:i + 8] for i in range(0, 64, 8))) == k
    assert key_from_hex("\n" + h + "\n") == k


@pytest.mark.parametrize("bad", ["zz", "abc", "0x" + "00" * 32, "g" * 64, "ab cd e"])
def test_invalid_hex_keys_rejected(bad):
    with pytest.raises(ParameterError):
        key_from_hex(bad)
