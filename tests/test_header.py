import pytest

from fileenc import FormatError, ParameterError
from fileenc.header import (HEADER_SIZE, MAX_SCRYPT_MEM, Algorithm, Header,
                            KeyMode)

from .helpers import PASSWORD, enc
from .reference import ref_header


def raw_header(**over):
    base = dict(algorithm=Algorithm.AES_GCM, key_mode=KeyMode.RAW, key_length=32,
                chunk_size=65536, nonce_prefix=bytes(7), salt=bytes(16))
    base.update(over)
    return Header(**base)


def pw_header(**over):
    base = dict(algorithm=Algorithm.AES_GCM, key_mode=KeyMode.PASSWORD, key_length=32,
                chunk_size=65536, nonce_prefix=bytes(7), salt=bytes(range(16)),
                scrypt_log2n=15, scrypt_r=8, scrypt_p=1)
    base.update(over)
    return Header(**base)


def test_header_is_38_bytes_and_matches_independent_layout():
    h = raw_header(nonce_prefix=bytes(range(7)))
    assert HEADER_SIZE == 38 and len(h.pack()) == 38
    assert h.pack() == ref_header(1, 1, 32, 65536, bytes(range(7)))


@pytest.mark.parametrize("h", [raw_header(), pw_header(), raw_header(algorithm=Algorithm.CHACHA20_POLY1305),
                               raw_header(algorithm=Algorithm.AES_GCM, key_length=16)])
def test_pack_parse_roundtrip(h):
    assert Header.parse(h.pack()) == h


@pytest.mark.parametrize("n", range(0, 38))
def test_every_truncated_header_length_rejected(n):
    with pytest.raises(FormatError):
        Header.parse(raw_header().pack()[:n])


def test_oversized_header_blob_rejected():
    with pytest.raises(FormatError):
        Header.parse(raw_header().pack() + b"\x00")


def _mut(h: Header, off: int, data: bytes) -> bytes:
    b = bytearray(h.pack()); b[off:off + len(data)] = data; return bytes(b)


@pytest.mark.parametrize("label,off,data", [
    ("bad magic", 0, b"XXXX"), ("version 0", 4, b"\x00"), ("version 2", 4, b"\x02"),
    ("algorithm 0", 5, b"\x00"), ("algorithm 3", 5, b"\x03"), ("algorithm 255", 5, b"\xff"),
    ("key mode 0", 6, b"\x00"), ("key mode 3", 6, b"\x03"),
    ("key length 0", 7, b"\x00"), ("key length 5", 7, b"\x05"), ("key length 33", 7, b"\x21"),
    ("chunk size 0", 8, (0).to_bytes(4, "big")), ("chunk size 1023", 8, (1023).to_bytes(4, "big")),
    ("chunk size 16MiB+1", 8, (16 * 1024 * 1024 + 1).to_bytes(4, "big")),
    ("chunk size 4GiB-1", 8, (2**32 - 1).to_bytes(4, "big")),
    ("stray salt in raw mode", 19, b"\x01"), ("stray log2N in raw mode", 35, b"\x0f"),
    ("stray r in raw mode", 36, b"\x08"), ("stray p in raw mode", 37, b"\x01"),
])
def test_invalid_raw_headers_rejected(label, off, data):
    with pytest.raises(FormatError):
        Header.parse(_mut(raw_header(), off, data))


def test_chacha_requires_32_byte_key():
    blob = _mut(raw_header(algorithm=Algorithm.CHACHA20_POLY1305), 7, b"\x10")  # key length 16
    with pytest.raises(FormatError):
        Header.parse(blob)


@pytest.mark.parametrize("label,off,val", [
    ("log2N 13 (too weak)", 35, 13), ("log2N 18 (256 MiB)", 35, 18), ("log2N 30", 35, 30),
    ("log2N 255", 35, 255), ("r 0", 36, 0), ("r 17", 36, 17), ("p 0", 37, 0), ("p 5", 37, 5),
    ("r 16 with log2N 17 = 256 MiB", None, None),
])
def test_hostile_scrypt_parameters_rejected_before_any_kdf_work(label, off, val):
    b = bytearray(pw_header().pack())
    if off is None:
        b[35], b[36] = 17, 16
    else:
        b[off] = val
    with pytest.raises(FormatError):
        Header.parse(bytes(b))


def test_scrypt_memory_boundary_is_exactly_the_cap():
    assert 128 * (1 << 17) * 8 == MAX_SCRYPT_MEM
    Header.parse(pw_header(scrypt_log2n=17).pack())          # exactly at the cap: allowed
    with pytest.raises(FormatError):
        Header.parse(_mut(pw_header(), 35, b"\x12"))          # 2^18: over the cap


def test_pack_refuses_invalid_parameters_as_caller_error():
    with pytest.raises(ParameterError):
        raw_header(key_length=20).pack()
    with pytest.raises(ParameterError):
        raw_header(chunk_size=10).pack()
    with pytest.raises(ParameterError):
        pw_header(scrypt_log2n=30).pack()


def test_engine_writes_headers_that_parse_back():
    blob, _ = enc(b"x", password=PASSWORD)
    h = Header.parse(blob[:HEADER_SIZE])
    assert h.key_mode is KeyMode.PASSWORD and (h.scrypt_log2n, h.scrypt_r, h.scrypt_p) == (15, 8, 1)
