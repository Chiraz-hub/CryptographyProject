import os

import pytest

from fileenc import (AuthenticationError, FormatError, ParameterError,
                     atomic_write, decrypt_file, encrypt_file)

from .helpers import PASSWORD


def names(d):
    return sorted(os.listdir(d))


@pytest.fixture
def src(tmp_path):
    p = tmp_path / "plain.bin"
    p.write_bytes(os.urandom(5000))
    return p


def test_encrypt_then_decrypt_file_restores_exact_bytes(tmp_path, src):
    enc_p, out_p = tmp_path / "plain.bin.enc", tmp_path / "restored.bin"
    key = encrypt_file(str(src), str(enc_p))
    decrypt_file(str(enc_p), str(out_p), key=key)
    assert out_p.read_bytes() == src.read_bytes()
    assert names(tmp_path) == ["plain.bin", "plain.bin.enc", "restored.bin"]   # no temp files


def test_password_file_roundtrip(tmp_path, src):
    e, o = tmp_path / "e", tmp_path / "o"
    assert encrypt_file(str(src), str(e), password=PASSWORD) is None
    decrypt_file(str(e), str(o), password=PASSWORD)
    assert o.read_bytes() == src.read_bytes()


def test_empty_file_roundtrip(tmp_path):
    s = tmp_path / "empty"; s.write_bytes(b"")
    e, o = tmp_path / "empty.enc", tmp_path / "empty.out"
    key = encrypt_file(str(s), str(e))
    decrypt_file(str(e), str(o), key=key)
    assert o.read_bytes() == b""


def test_source_file_is_never_modified(tmp_path, src):
    before, mtime = src.read_bytes(), src.stat().st_mtime_ns
    encrypt_file(str(src), str(tmp_path / "x.enc"))
    assert src.read_bytes() == before and src.stat().st_mtime_ns == mtime


def test_refuses_to_overwrite_existing_destination(tmp_path, src):
    dst = tmp_path / "x.enc"; dst.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        encrypt_file(str(src), str(dst))
    assert dst.read_bytes() == b"precious"


def test_refuses_destination_equal_to_source(tmp_path, src):
    before = src.read_bytes()
    with pytest.raises(ParameterError):
        encrypt_file(str(src), str(src), overwrite=True)
    with pytest.raises(ParameterError):
        decrypt_file(str(src), str(src), key=bytes(32), overwrite=True)
    assert src.read_bytes() == before                       # not even clobbered by overwrite=True


def test_explicit_overwrite_replaces_atomically(tmp_path, src):
    dst = tmp_path / "x.enc"; dst.write_bytes(b"old")
    key = encrypt_file(str(src), str(dst), overwrite=True)
    out = tmp_path / "o"; decrypt_file(str(dst), str(out), key=key)
    assert out.read_bytes() == src.read_bytes()


def test_failed_encryption_leaves_existing_destination_and_no_temp(tmp_path, src):
    dst = tmp_path / "x.enc"; dst.write_bytes(b"keep me")
    with pytest.raises(ParameterError):
        encrypt_file(str(src), str(dst), overwrite=True, key_size=7)
    assert dst.read_bytes() == b"keep me"
    assert names(tmp_path) == ["plain.bin", "x.enc"]


def test_missing_source_leaves_nothing_behind(tmp_path):
    with pytest.raises(FileNotFoundError):
        encrypt_file(str(tmp_path / "nope"), str(tmp_path / "nope.enc"))
    assert names(tmp_path) == []


# ---------- decryption never exposes partial output ----------
@pytest.mark.parametrize("damage", ["truncate", "flip", "garbage", "append"])
def test_failed_decryption_leaves_no_output_and_no_temp(tmp_path, src, damage):
    e = tmp_path / "e.enc"; key = encrypt_file(str(src), str(e), chunk_size=1024)
    blob = e.read_bytes()
    bad = {"truncate": blob[:-3], "flip": blob[:2000] + bytes([blob[2000] ^ 1]) + blob[2001:],
           "garbage": os.urandom(300), "append": blob + b"x"}[damage]
    e.write_bytes(bad)
    out = tmp_path / "out"
    with pytest.raises((AuthenticationError, FormatError)):
        decrypt_file(str(e), str(out), key=key)
    assert not out.exists()                                  # plaintext never became visible
    assert names(tmp_path) == ["e.enc", "plain.bin"]         # and no .fenc-*.tmp left over


def test_wrong_key_leaves_no_output(tmp_path, src):
    e = tmp_path / "e.enc"; encrypt_file(str(src), str(e))
    with pytest.raises(AuthenticationError):
        decrypt_file(str(e), str(tmp_path / "o"), key=os.urandom(32))
    assert names(tmp_path) == ["e.enc", "plain.bin"]


def test_decrypt_file_refuses_to_overwrite(tmp_path, src):
    e, o = tmp_path / "e", tmp_path / "o"
    key = encrypt_file(str(src), str(e)); o.write_bytes(b"mine")
    with pytest.raises(FileExistsError):
        decrypt_file(str(e), str(o), key=key)
    assert o.read_bytes() == b"mine"


# ---------- interrupted operations ----------
def test_failure_midway_through_writing_removes_partial_output(tmp_path):
    dst = tmp_path / "out"
    def writer(f):
        f.write(b"partial plaintext")
        raise RuntimeError("disk exploded")
    with pytest.raises(RuntimeError):
        atomic_write(str(dst), writer)
    assert names(tmp_path) == []                             # neither dst nor a temp file


def test_keyboard_interrupt_is_cleaned_up_too(tmp_path):
    def writer(f):
        f.write(b"partial")
        raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        atomic_write(str(tmp_path / "out"), writer)
    assert names(tmp_path) == []


def test_read_error_midway_through_source_leaves_no_partial_encryption(tmp_path, monkeypatch):
    big = tmp_path / "big"; big.write_bytes(os.urandom(300_000))
    import builtins
    real_open = builtins.open
    class Flaky:
        def __init__(self, f): self.f, self.n = f, 0
        def read(self, k=-1):
            self.n += 1
            if self.n == 3: raise OSError("simulated I/O error")
            return self.f.read(k)
        def __enter__(self): return self
        def __exit__(self, *a): self.f.close()
    def fake_open(p, mode="r", *a, **k):
        f = real_open(p, mode, *a, **k)
        return Flaky(f) if str(p) == str(big) and "rb" in mode else f
    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(OSError):
        encrypt_file(str(big), str(tmp_path / "big.enc"), chunk_size=1024)
    monkeypatch.undo()
    assert names(tmp_path) == ["big"]


def test_atomic_write_creates_destination_only_on_success(tmp_path):
    dst = tmp_path / "out"
    seen = {}
    def writer(f):
        f.write(b"data"); f.flush()
        seen["exists_during"] = dst.exists()
    atomic_write(str(dst), writer)
    assert seen["exists_during"] is False and dst.read_bytes() == b"data"
