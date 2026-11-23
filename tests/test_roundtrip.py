import io
import os
import tracemalloc

import pytest

from fileenc import Algorithm, decrypt_stream, encrypt_stream
from fileenc.header import HEADER_SIZE

from .helpers import PASSWORD, dec, enc

CASES = [(Algorithm.AES_GCM, 16), (Algorithm.AES_GCM, 24), (Algorithm.AES_GCM, 32),
         (Algorithm.CHACHA20_POLY1305, 32)]
CS = 1024
SIZES = [0, 1, CS - 1, CS, CS + 1, 2 * CS, 5 * CS + 7]


@pytest.mark.parametrize("alg,ks", CASES)
@pytest.mark.parametrize("n", SIZES)
def test_raw_key_roundtrip_boundary_sizes(alg, ks, n):
    data = os.urandom(n)
    blob, key = enc(data, algorithm=alg, key_size=ks, chunk_size=CS)
    assert len(key) == ks
    assert dec(blob, key=key) == data


@pytest.mark.parametrize("alg,ks", CASES)
@pytest.mark.parametrize("n", [0, 1, CS + 1, 5 * CS + 7])
def test_password_roundtrip(alg, ks, n):
    data = os.urandom(n)
    blob, key = enc(data, algorithm=alg, key_size=ks, chunk_size=CS, password=PASSWORD)
    assert key is None
    assert dec(blob, password=PASSWORD) == data


@pytest.mark.parametrize("n", SIZES)
def test_output_length_is_header_plus_data_plus_one_tag_per_chunk(n):
    blob, _ = enc(os.urandom(n), chunk_size=CS)
    chunks = max(1, -(-n // CS))  # an exact multiple does NOT add an empty extra chunk
    assert len(blob) == HEADER_SIZE + n + 16 * chunks


CONTENT = {
    "empty": b"",
    "ascii text": b"The quick brown fox jumps over the lazy dog.\n" * 200,
    "unicode text": ("ملف تجريبي — fichier d'essai — 测试文件 🔐\n" * 100).encode("utf-8"),
    "crlf preserved": b"line1\r\nline2\r\n\r\n" * 300,
    "all zero bytes": bytes(10_000),
    "all 0xFF bytes": b"\xff" * 10_000,
    "every byte value": bytes(range(256)) * 40,
    "random binary": os.urandom(12_345),
}


@pytest.mark.parametrize("name", CONTENT)
def test_content_types_restored_exactly(name):
    data = CONTENT[name]
    blob, key = enc(data, chunk_size=CS)
    assert dec(blob, key=key) == data


def test_default_chunk_size_multi_chunk_3mb():
    data = os.urandom(3_000_000)
    blob, key = enc(data)  # default 64 KiB chunks -> 46 chunks
    assert dec(blob, key=key) == data


@pytest.mark.slow
def test_8mb_with_both_algorithms():
    data = os.urandom(8 * 1024 * 1024 + 123)
    for alg, ks in [(Algorithm.AES_GCM, 32), (Algorithm.CHACHA20_POLY1305, 32)]:
        blob, key = enc(data, algorithm=alg, key_size=ks)
        assert dec(blob, key=key) == data


def test_no_plaintext_secrets_or_keys_leak_into_output():
    data = b"SENSITIVE-PATTERN-1234567890" * 200
    blob, key = enc(data, chunk_size=CS)
    assert b"SENSITIVE-PATTERN" not in blob
    assert key not in blob
    pblob, _ = enc(data, chunk_size=CS, password=PASSWORD)
    assert PASSWORD.encode() not in pblob and b"SENSITIVE-PATTERN" not in pblob


def test_fresh_randomness_for_every_file():
    a, ka = enc(b"same input", chunk_size=CS)
    b, kb = enc(b"same input", chunk_size=CS)
    assert ka != kb and a != b
    assert a[12:19] != b[12:19]                    # nonce prefixes differ
    pa, _ = enc(b"same input", chunk_size=CS, password=PASSWORD)
    pb, _ = enc(b"same input", chunk_size=CS, password=PASSWORD)
    assert pa[19:35] != pb[19:35]                  # scrypt salts differ
    assert pa != pb


def test_nonces_never_repeat_within_a_file():
    # The nonce is prefix|counter|flag; all counters must differ across chunks.
    from fileenc.engine import chunk_nonce
    seen = {chunk_nonce(bytes(7), i, False) for i in range(5000)}
    assert len(seen) == 5000
    assert chunk_nonce(bytes(7), 3, True) != chunk_nonce(bytes(7), 3, False)


class _Zeros:
    """File-like source of `total` zero bytes that never holds them in memory."""
    def __init__(self, total):
        self.left = total
    def read(self, n=-1):
        n = self.left if n < 0 else min(n, self.left)
        self.left -= n
        return bytes(n)


class _Sink:
    def __init__(self):
        self.n = 0
    def write(self, b):
        self.n += len(b)
        return len(b)


@pytest.mark.slow
def test_encrypt_and_decrypt_are_truly_streaming(tmp_path):
    """24 MiB through the engine must not need anywhere near 24 MiB of RAM."""
    total = 24 * 1024 * 1024
    ct_path = tmp_path / "big.enc"
    tracemalloc.start()
    with open(ct_path, "wb") as out:
        key = encrypt_stream(_Zeros(total), out)
    _, enc_peak = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    sink = _Sink()
    with open(ct_path, "rb") as src:
        decrypt_stream(src, sink, key=key)
    _, dec_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert sink.n == total
    assert enc_peak < 6 * 1024 * 1024, f"encrypt peak {enc_peak} bytes"
    assert dec_peak < 6 * 1024 * 1024, f"decrypt peak {dec_peak} bytes"


def test_short_reads_from_source_do_not_corrupt_output():
    class Trickle:  # returns at most 7 bytes per read(): a short read is NOT EOF
        def __init__(self, data): self.b = io.BytesIO(data)
        def read(self, n=-1): return self.b.read(min(7, n if n > 0 else 7))
    data = os.urandom(3 * CS + 5)
    dst = io.BytesIO()
    key = encrypt_stream(Trickle(data), dst, chunk_size=CS)
    assert dec(dst.getvalue(), key=key) == data
