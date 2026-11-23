import os
import pathlib
import re
import time

import pytest

import app as appmod
from app import create_app
from fileenc import encrypt_stream
from tests.helpers import PASSWORD

ENC = {"algorithm": "aes-gcm", "key_size": "256", "key_mode": "password",
       "password": PASSWORD, "password_confirm": PASSWORD}
RAW = {"algorithm": "chacha20-poly1305", "key_mode": "raw"}
KEY_RE = re.compile(rb'value="([0-9a-f]{64})"')
LINK_RE = re.compile(rb"/download/([\w-]+)")


# ============================ routes & roundtrips ============================
def test_index_renders_both_workflows(rig):
    r, body = rig.get("/")
    assert r.status_code == 200 and b'action="/encrypt"' in body and b'action="/decrypt"' in body
    assert b"csrf_token" in body


def test_static_assets_served(rig):
    assert rig.get("/static/styles.css")[0].status_code == 200
    assert rig.get("/static/app.js")[0].status_code == 200


@pytest.mark.parametrize("fields", [
    {**ENC, "key_size": "128"}, {**ENC, "key_size": "192"}, {**ENC, "key_size": "256"},
    {**ENC, "algorithm": "chacha20-poly1305"},
    {**ENC, "algorithm": "chacha20-poly1305", "key_size": "128"},   # ignored for ChaCha
])
def test_password_roundtrip_through_flask(rig, fields):
    r, blob = rig.post("/encrypt", fields, content=b"hello flask")
    assert r.status_code == 200 and blob[:4] == b"FENC"
    assert int(r.headers["Content-Length"]) == len(blob)
    r2, plain = rig.post("/decrypt", {"password": PASSWORD}, fname="a.txt.enc", content=blob)
    assert r2.status_code == 200 and plain == b"hello flask"
    assert rig.leftovers() == []


@pytest.mark.parametrize("content", [b"", os.urandom(1_000_000), bytes(range(256)) * 50,
                                     "نص عربي 🔐".encode()])
def test_various_files_roundtrip(rig, content):
    _, blob = rig.post("/encrypt", ENC, content=content)
    r, plain = rig.post("/decrypt", {"password": PASSWORD}, fname="x.enc", content=blob)
    assert r.status_code == 200 and plain == content


@pytest.mark.parametrize("upload,enc_name", [
    ("a.txt", "a.txt.enc"), ("....", "file.enc"), ("../../etc/passwd", "etc_passwd.enc"),
    ("..\\..\\evil.txt", "evil.txt.enc"), ("my file (1).pdf", "my_file_1.pdf.enc"),
])
def test_download_names_are_sanitised(rig, upload, enc_name):
    r, _ = rig.post("/encrypt", ENC, fname=upload)
    assert f'filename={enc_name}' in r.headers["Content-Disposition"]
    assert "attachment" in r.headers["Content-Disposition"]
    assert rig.leftovers() == []


@pytest.mark.parametrize("upload,out_name", [
    ("a.txt.enc", "a.txt"), ("report.final.pdf.ENC", "report.final.pdf"),
    ("....", "decrypted_file"), (".enc", "decrypted_file"),
    ("noextension", "decrypted_file"),   # design: only a .enc suffix is stripped; else generic name
])
def test_decrypt_names(rig, upload, out_name):
    _, blob = rig.post("/encrypt", ENC)
    r, _ = rig.post("/decrypt", {"password": PASSWORD}, fname=upload, content=blob)
    assert r.status_code == 200 and f"filename={out_name}" in r.headers["Content-Disposition"]


def test_path_traversal_filename_writes_nothing_outside_work_root(rig, tmp_path):
    before = set(os.listdir(tmp_path))
    rig.post("/encrypt", ENC, fname="../../../../tmp/pwned")
    assert set(os.listdir(tmp_path)) == before and not os.path.exists("/tmp/pwned.enc")


# ============================ raw-key flow ============================
def test_raw_key_flow_is_one_time_and_key_stays_out_of_urls_and_file(rig):
    r, page = rig.post("/encrypt", RAW)
    key_hex, link = KEY_RE.search(page).group(1), LINK_RE.search(page).group(1).decode()
    assert r.headers["Cache-Control"] == "no-store"
    assert key_hex not in LINK_RE.search(page).group(0)
    assert len(rig.leftovers()) == 1                       # ciphertext held while pending
    d1, ct = rig.get(f"/download/{link}")
    assert d1.status_code == 200 and ct[:4] == b"FENC" and bytes.fromhex(key_hex.decode()) not in ct
    assert rig.get(f"/download/{link}")[0].status_code == 404        # single use
    assert rig.leftovers() == []                                       # deleted after serving
    r2, plain = rig.post("/decrypt", {"key": key_hex.decode()}, fname="a.txt.enc", content=ct)
    assert plain == b"hello"
    spaced = " ".join(key_hex.decode()[i:i + 8] for i in range(0, 64, 8))
    assert rig.post("/decrypt", {"key": spaced}, fname="a.enc", content=ct)[1] == b"hello"


def test_expired_download_token_is_gone_and_swept(make_rig):
    rig = make_rig(ttl=-1)
    _, page = rig.post("/encrypt", RAW)
    link = LINK_RE.search(page).group(1).decode()
    assert rig.get(f"/download/{link}")[0].status_code == 404
    assert rig.leftovers() == []


def test_random_token_guess_is_404(rig):
    assert rig.get("/download/" + "A" * 43)[0].status_code == 404


# ============================ decryption failures ============================
@pytest.fixture
def blob(rig):
    return rig.post("/encrypt", ENC, content=b"top secret plaintext")[1]


def _expect_400(rig, r, body, needle):
    assert r.status_code == 400 and needle in body
    assert b"top secret plaintext" not in body and b"Traceback" not in body
    assert rig.leftovers() == []


def test_wrong_password(rig, blob):
    r, b = rig.post("/decrypt", {"password": "definitely not it"}, fname="a.enc", content=blob)
    _expect_400(rig, r, b, b"wrong key or password")


def test_tampered_ciphertext(rig, blob):
    t = bytearray(blob); t[-1] ^= 1
    r, b = rig.post("/decrypt", {"password": PASSWORD}, fname="a.enc", content=bytes(t))
    _expect_400(rig, r, b, b"wrong key or password")


def test_truncated_ciphertext(rig, blob):
    r, b = rig.post("/decrypt", {"password": PASSWORD}, fname="a.enc", content=blob[:-1])
    _expect_400(rig, r, b, b"wrong key or password")


def test_not_a_fenc_file(rig):
    r, b = rig.post("/decrypt", {"password": PASSWORD}, fname="x.enc", content=b"plain text file")
    _expect_400(rig, r, b, b"does not look like")


def test_missing_secret_explains_what_is_needed(rig, blob):
    r, b = rig.post("/decrypt", {}, fname="a.enc", content=blob)
    _expect_400(rig, r, b, b"password")
    _, page = rig.post("/encrypt", RAW)
    ct = rig.get("/download/" + LINK_RE.search(page).group(1).decode())[1]
    r, b = rig.post("/decrypt", {}, fname="a.enc", content=ct)
    _expect_400(rig, r, b, b"raw key")


def test_wrong_and_malformed_keys(rig):
    _, page = rig.post("/encrypt", RAW)
    ct = rig.get("/download/" + LINK_RE.search(page).group(1).decode())[1]
    r, b = rig.post("/decrypt", {"key": "00" * 32}, fname="a.enc", content=ct)
    _expect_400(rig, r, b, b"wrong key or password")
    r, b = rig.post("/decrypt", {"key": "zz"}, fname="a.enc", content=ct)
    _expect_400(rig, r, b, b"hex")
    r, b = rig.post("/decrypt", {"key": "00" * 16}, fname="a.enc", content=ct)
    _expect_400(rig, r, b, b"wrong key length")


def test_hostile_scrypt_header_is_rejected_fast(rig):
    import io
    d = io.BytesIO(); encrypt_stream(io.BytesIO(b"x"), d, password=PASSWORD)
    hostile = bytearray(d.getvalue()); hostile[35] = 30                 # N = 2**30
    t0 = time.time()
    r, b = rig.post("/decrypt", {"password": PASSWORD}, fname="e.enc", content=bytes(hostile))
    assert r.status_code == 400 and b"does not look like" in b and time.time() - t0 < 1.0


# ============================ input validation ============================
@pytest.mark.parametrize("label,over", [
    ("unknown algorithm", {"algorithm": "des"}), ("legacy rc4", {"algorithm": "rc4"}),
    ("empty algorithm", {"algorithm": ""}), ("non-numeric key size", {"key_size": "abc"}),
    ("unsupported key size", {"key_size": "100"}), ("short password", {"password": "short", "password_confirm": "short"}),
    ("password mismatch", {"password_confirm": "something else entirely"}),
    ("missing key mode", {"key_mode": None}), ("bogus key mode", {"key_mode": "magic"}),
])
def test_encrypt_rejects_bad_input(rig, label, over):
    fields = {**ENC, **over}
    fields = {k: v for k, v in fields.items() if v is not None}
    r, b = rig.post("/encrypt", fields)
    assert r.status_code == 400 and b"Traceback" not in b
    assert rig.leftovers() == []


def test_missing_file_rejected(rig):
    r, _ = rig.post("/encrypt", ENC, filefield=None)
    assert r.status_code == 400
    r, _ = rig.post("/decrypt", {"password": PASSWORD}, filefield=None)
    assert r.status_code == 400


def test_password_is_never_echoed_back(rig):
    r, b = rig.post("/encrypt", {**ENC, "password_confirm": "does not match!!"})
    assert PASSWORD.encode() not in b


# ============================ CSRF ============================
@pytest.mark.parametrize("path,fields", [("/encrypt", ENC), ("/decrypt", {"password": PASSWORD})])
def test_missing_or_forged_csrf_token_rejected(rig, path, fields):
    r, b = rig.post(path, fields, token=None)
    assert r.status_code == 400 and b"session expired" in b
    r, b = rig.post(path, fields, token="forged-token-value")
    assert r.status_code == 400
    assert rig.leftovers() == []                                    # no work started


def test_token_from_another_session_rejected(make_rig):
    victim, attacker = make_rig(), make_rig()
    stolen = attacker.token()
    r, _ = victim.post("/encrypt", ENC, token=stolen)
    assert r.status_code == 400


def test_get_download_needs_no_csrf_token(rig):
    _, page = rig.post("/encrypt", RAW)
    assert rig.get("/download/" + LINK_RE.search(page).group(1).decode())[0].status_code == 200


def test_csrf_field_present_in_every_form(rig):
    _, body = rig.get("/")
    assert body.count(b'name="csrf_token"') == 2


# ============================ headers / CSP / cookies ============================
def test_security_headers_on_pages(rig):
    h = rig.get("/")[0].headers
    csp = h["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe" not in csp
    assert "frame-ancestors 'none'" in csp and "form-action 'self'" in csp and "base-uri 'none'" in csp
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer" and h["Cache-Control"] == "no-store"


def test_downloads_are_attachments_with_safe_headers(rig):
    r, _ = rig.post("/encrypt", ENC)
    assert "attachment" in r.headers["Content-Disposition"]
    assert r.headers["Content-Type"] == "application/octet-stream"
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["Cache-Control"] == "no-store"
    assert "Content-Security-Policy" in r.headers


def test_pages_contain_no_inline_script_handlers_or_styles(rig):
    inline = re.compile(rb"<script(?![^>]*\bsrc=)|\son\w+\s*=|\sstyle\s*=|javascript:", re.I)
    _, main = rig.get("/")
    _, result = rig.post("/encrypt", RAW)
    _, error = rig.post("/encrypt", {**ENC, "algorithm": "des"})
    for page in (main, result, error):
        assert not inline.search(page)


def test_session_cookie_flags(make_rig):
    assert "HttpOnly" in (c := make_rig().client.get("/").headers["Set-Cookie"]) and "SameSite=Lax" in c


def test_https_mode_adds_secure_cookie_and_hsts(make_rig, monkeypatch):
    monkeypatch.setenv("FENC_HTTPS", "1")
    r = make_rig().client.get("/")
    assert "Secure" in r.headers["Set-Cookie"] and "Strict-Transport-Security" in r.headers


def test_404_page_is_generic(rig):
    r, b = rig.get("/nope")
    assert r.status_code == 404 and b"Traceback" not in b


# ============================ secrets / debug ============================
def test_secret_key_is_random_per_instance_and_never_hardcoded(make_rig):
    a, b = make_rig().app.config["SECRET_KEY"], make_rig().app.config["SECRET_KEY"]
    assert a != b and len(a) == 64
    assert not re.search(r"SECRET_KEY\"?\]?\s*=\s*[\"'][^\"']+[\"']", pathlib.Path(appmod.__file__).read_text())


def test_secret_key_from_environment(make_rig, monkeypatch):
    monkeypatch.setenv("FENC_SECRET_KEY", "from-the-environment")
    assert make_rig().app.config["SECRET_KEY"] == "from-the-environment"


def test_debug_is_off_by_default():
    assert create_app().debug is False
    assert "debug=True" not in pathlib.Path(appmod.__file__).read_text()


# ============================ resource limits ============================
def test_no_free_crypto_slot_gives_503_and_no_leftovers(make_rig):
    rig = make_rig(FENC_MAX_CONCURRENT=0)
    r, b = rig.post("/encrypt", ENC)
    assert r.status_code == 503 and r.headers["Retry-After"] == "5" and rig.leftovers() == []
    assert rig.post("/decrypt", {"password": PASSWORD}, content=b"x")[0].status_code == 503


def test_slot_is_released_after_every_kind_of_failure(make_rig, monkeypatch):
    rig = make_rig(FENC_MAX_CONCURRENT=1)
    good = rig.post("/encrypt", ENC)[1]
    rig.post("/decrypt", {"password": "wrong password!"}, fname="a.enc", content=good)   # auth failure
    rig.post("/decrypt", {"password": PASSWORD}, fname="a.enc", content=b"garbage")      # format failure
    rig.post("/encrypt", {**ENC, "password": "x" * 12 + "", "password_confirm": "x" * 12})
    def boom(*a, **k): raise RuntimeError("kaboom internal detail")
    monkeypatch.setattr(appmod, "encrypt_stream", boom)
    r500, b500 = rig.post("/encrypt", ENC)                                              # internal error
    monkeypatch.undo()
    assert r500.status_code == 500 and b"kaboom" not in b500 and b"Nothing was saved" in b500
    assert rig.leftovers() == []
    assert rig.post("/encrypt", ENC)[0].status_code == 200                              # slot still free


def test_pending_download_cap(make_rig):
    rig = make_rig(FENC_MAX_PENDING=1)
    assert rig.post("/encrypt", RAW)[0].status_code == 200
    assert rig.post("/encrypt", RAW)[0].status_code == 503
    assert rig.post("/encrypt", ENC)[0].status_code == 200            # password mode unaffected


def test_sweep_removes_stale_orphans_but_never_live_downloads(rig):
    old = time.time() - 7200
    orphan = rig.root / "orphan"; orphan.mkdir(); os.utime(orphan, (old, old))
    (rig.root / "fresh").mkdir()
    _, page = rig.post("/encrypt", RAW)
    live = next(p for p in rig.root.iterdir() if p.name not in ("orphan", "fresh"))
    os.utime(live, (old, old))
    rig.get("/")
    assert not orphan.exists() and (rig.root / "fresh").exists()
    assert rig.get("/download/" + LINK_RE.search(page).group(1).decode())[0].status_code == 200


def test_oversize_upload_is_413_even_with_valid_token(rig):
    rig.app.config["MAX_CONTENT_LENGTH"] = 1000
    r, b = rig.post("/encrypt", ENC, content=os.urandom(5000))
    assert r.status_code == 413 and b"too large" in b and rig.leftovers() == []


# ============================ logs ============================
def test_no_secret_ever_reaches_the_logs(rig, caplog, monkeypatch):
    import logging
    caplog.set_level(logging.DEBUG)
    blob = rig.post("/encrypt", ENC)[1]
    rig.post("/decrypt", {"password": "another secret pw 1"}, fname="a.enc", content=blob)
    rig.post("/decrypt", {"password": PASSWORD}, fname="x.enc", content=b"garbage")
    rig.post("/encrypt", {**ENC, "password_confirm": "mismatch mismatch"})
    def boom(*a, **k): raise RuntimeError("internal failure")
    monkeypatch.setattr(appmod, "encrypt_stream", boom)
    rig.post("/encrypt", ENC)
    monkeypatch.undo()
    _, page = rig.post("/encrypt", RAW)
    key_hex = KEY_RE.search(page).group(1).decode()
    assert "internal failure" in caplog.text                      # the scan is meaningful
    for secret in (PASSWORD, "another secret pw 1", "mismatch mismatch", key_hex):
        assert secret not in caplog.text
