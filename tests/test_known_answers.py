"""Known-answer tests: published vectors + cross-implementation + golden files.

Round-trip tests alone cannot prove correctness (a consistently broken design
round-trips fine). These pin behaviour to external or independent references.
"""
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from fileenc import Algorithm
from fileenc.kdf import derive_key

from .helpers import dec, enc
from .reference import ref_decrypt, ref_encrypt

# ---------- RFC 8439 section 2.8.2 ----------
def test_chacha20poly1305_rfc8439_vector():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    expected_ct = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116")
    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    out = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    assert out[:-16] == expected_ct
    assert out[-16:] == expected_tag


# ---------- McGrew & Viega GCM spec test cases ----------
_P = ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
_A = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
_IV = "cafebabefacedbaddecaf888"
GCM_VECTORS = [
    ("TC2 AES-128, zeros", "00" * 16, "00" * 12, "00" * 16, "",
     "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
    ("TC4 AES-128 + AAD", "feffe9928665731c6d6a8f9467308308", _IV, _P, _A,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"),
    ("TC10 AES-192 + AAD", "feffe9928665731c6d6a8f9467308308feffe9928665731c", _IV, _P, _A,
     "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
     "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
     "2519498e80f1478f37ba55bd6d27618c"),
    ("TC16 AES-256 + AAD", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", _IV, _P, _A,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"),
]


@pytest.mark.parametrize("name,key,iv,pt,aad,ct,tag", GCM_VECTORS, ids=[v[0] for v in GCM_VECTORS])
def test_aesgcm_published_vectors(name, key, iv, pt, aad, ct, tag):
    out = AESGCM(bytes.fromhex(key)).encrypt(bytes.fromhex(iv), bytes.fromhex(pt), bytes.fromhex(aad))
    assert out == bytes.fromhex(ct) + bytes.fromhex(tag)


# ---------- RFC 7914 section 12 (via OUR derive_key wrapper) ----------
def test_scrypt_rfc7914_empty_password():
    # P="", S="", N=16, r=1, p=1, dkLen=64
    got = derive_key("", b"", 4, 1, 1, 64)
    assert got.hex() == ("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                         "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")


def test_scrypt_rfc7914_pleaseletmein():
    # P="pleaseletmein", S="SodiumChloride", N=16384, r=8, p=1, dkLen=64
    got = derive_key("pleaseletmein", b"SodiumChloride", 14, 8, 1, 64)
    assert got.hex() == ("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
                         "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887")


# ---------- cross-implementation: engine vs independent reference ----------
CASES = [(Algorithm.AES_GCM, 16), (Algorithm.AES_GCM, 24), (Algorithm.AES_GCM, 32),
         (Algorithm.CHACHA20_POLY1305, 32)]
SIZES = [0, 1, 1023, 1024, 1025, 2048, 5127]


@pytest.mark.parametrize("alg,ks", CASES)
@pytest.mark.parametrize("n", SIZES)
def test_engine_output_decrypts_with_reference(alg, ks, n):
    data = os.urandom(n)
    blob, key = enc(data, algorithm=alg, key_size=ks, chunk_size=1024)
    assert ref_decrypt(blob, key=key) == data


@pytest.mark.parametrize("alg,ks", CASES)
@pytest.mark.parametrize("n", SIZES)
def test_engine_decrypts_reference_output(alg, ks, n):
    data, key = os.urandom(n), os.urandom(ks)
    blob = ref_encrypt(data, alg=int(alg), key=key, klen=ks, cs=1024)
    assert dec(blob, key=key) == data


def test_password_mode_cross_implementation():
    data = os.urandom(3000)
    blob, _ = enc(data, password="a perfectly fine passphrase", chunk_size=1024)
    assert ref_decrypt(blob, password="a perfectly fine passphrase") == data
    ref = ref_encrypt(data, password="another fine passphrase", params=(14, 8, 1))
    assert dec(ref, password="another fine passphrase") == data


# ---------- golden files: FENC v1 must stay decryptable forever ----------
# Generated once by tests/reference.py (independent of fileenc). Key/password
# are throwaway TEST VECTORS, not secrets. If these ever fail, the on-disk
# format changed: that needs a new format VERSION, not a silent edit.
GOLDEN_AESGCM_RAW = bytes.fromhex("46454e43010101200000040000010203040506000000000000000000000000000000000000003333fb1da7624c73ebab58abe5650a5bbcb777807152791b948ddc11c0a6ccb0966381c0285e")
GOLDEN_CHACHA_PASSWORD = bytes.fromhex("46454e4301020220000004000a0b0c0d0e0f101415161718191a1b1c1d1e1f202122230e080105b51e7330bbce21172d5649828bc928d411c2e025f61b7018e5c87cc6b2b6064bc254917bde")


def test_golden_v1_aesgcm_raw_key():
    assert dec(GOLDEN_AESGCM_RAW, key=bytes(range(32))) == b"FENC golden vector #1\n"


def test_golden_v1_chacha_password():
    assert dec(GOLDEN_CHACHA_PASSWORD, password="golden test password") == b"FENC golden vector #2\n"
