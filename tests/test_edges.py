"""Safety branches that normal flows never reach."""
import pytest

import app as appmod
from app import create_app
from fileenc import Algorithm, FormatError, ParameterError
from fileenc.engine import MAX_CHUNKS, chunk_nonce, make_aead
from fileenc.header import Header, KeyMode

from .helpers import PASSWORD
from .test_flask import ENC


def test_chunk_counter_overflow_is_refused_not_wrapped():
    """Wrapping the 4-byte counter would REUSE a nonce under the same key."""
    assert len(chunk_nonce(bytes(7), MAX_CHUNKS - 1, True)) == 12
    for bad in (MAX_CHUNKS, MAX_CHUNKS + 1):
        with pytest.raises(ParameterError):
            chunk_nonce(bytes(7), bad, False)


@pytest.mark.parametrize("alg,n", [(Algorithm.AES_GCM, 15), (Algorithm.AES_GCM, 33),
                                   (Algorithm.CHACHA20_POLY1305, 16), (Algorithm.CHACHA20_POLY1305, 31)])
def test_make_aead_rejects_wrong_key_lengths(alg, n):
    with pytest.raises(ParameterError):
        make_aead(alg, bytes(n))


@pytest.mark.parametrize("over", [dict(nonce_prefix=bytes(6)), dict(nonce_prefix=bytes(8)),
                                  dict(salt=bytes(15)), dict(salt=bytes(17))])
def test_header_rejects_wrong_nonce_or_salt_length(over):
    base = dict(algorithm=Algorithm.AES_GCM, key_mode=KeyMode.RAW, key_length=32,
                chunk_size=4096, nonce_prefix=bytes(7), salt=bytes(16))
    h = Header(**{**base, **over})
    with pytest.raises(FormatError):
        h.validate()
    with pytest.raises(ParameterError):
        h.pack()


def test_decrypt_internal_error_is_generic_cleaned_up_and_releases_slot(make_rig, monkeypatch):
    rig = make_rig(FENC_MAX_CONCURRENT=1)
    blob = rig.post("/encrypt", ENC)[1]
    def boom(*a, **k): raise RuntimeError("decrypt internals exploded")
    monkeypatch.setattr(appmod, "decrypt_stream", boom)
    r, body = rig.post("/decrypt", {"password": PASSWORD}, fname="a.enc", content=blob)
    monkeypatch.undo()
    assert r.status_code == 500 and b"exploded" not in body and b"Nothing was saved" in body
    assert rig.leftovers() == []
    assert rig.post("/decrypt", {"password": PASSWORD}, fname="a.enc", content=blob)[0].status_code == 200


def test_garbage_in_numeric_environment_variable_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("FENC_MAX_MB", "not-a-number")
    monkeypatch.setenv("FENC_MAX_CONCURRENT", "")
    app = create_app()
    assert app.config["MAX_CONTENT_LENGTH"] == 100 * 1024 * 1024
    assert app.config["FENC_MAX_CONCURRENT"] == 2
