import os, re, shutil, subprocess, sys, tempfile
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root; needs a POSIX shell (ulimit)
MUTANTS = [
 ("M1  final-chunk flag disabled (truncation defence off)", "fileenc/engine.py",
  '(b"\\x01" if is_final else b"\\x00")', 'b"\\x00"'),
 ("M2a header NOT used as AAD on encrypt", "fileenc/engine.py",
  "aead.encrypt(nonce, current, header_bytes)", 'aead.encrypt(nonce, current, b"")'),
 ("M2b header NOT used as AAD (both enc+dec)", "fileenc/engine.py",
  ["aead.encrypt(nonce, current, header_bytes)", "aead.decrypt(nonce, current, header_bytes)"],
  ['aead.encrypt(nonce, current, b"")', 'aead.decrypt(nonce, current, b"")']),
 ("M3  chunk counter stuck at 0 (nonce REUSE)", "fileenc/engine.py",
  'index.to_bytes(4, "big")', '(0).to_bytes(4, "big")'),
 ("M4  failed writes leave temp file behind", "fileenc/engine.py",
  "os.unlink(tmp_path)  # note: deletion is NOT secure erasure", "pass"),
 ("M5  password hashed with SHA-256 instead of scrypt", "fileenc/kdf.py",
  "    kdf = Scrypt(salt=salt, length=length, n=1 << log2n, r=r, p=p)\n    return kdf.derive(password.encode(\"utf-8\"))",
  "    import hashlib\n    return hashlib.sha256(password.encode() + salt).digest()[:length]"),
 ("M6  auth failure silently ends decryption (returns partial)", "fileenc/engine.py",
  "raise AuthenticationError(GENERIC_AUTH_MSG) from None", "return"),
 ("M7  hostile scrypt memory cap removed", "fileenc/header.py",
  "MAX_SCRYPT_MEM = 128 * 1024 * 1024", "MAX_SCRYPT_MEM = 10**18"),
 ("M8  CSRF protection removed", "app.py", "    CSRFProtect(app)\n", "    pass\n"),
 ("M9  download cleanup removed (the Phase 4 bug)", "app.py",
  "resp.call_on_close(lambda: rm(cleanup_dir))", "pass"),
 ("M10 CSP allows inline scripts", "app.py", "script-src 'self'", "script-src 'self' 'unsafe-inline'"),
 ("M11 raw key written into the .enc header area", "fileenc/engine.py",
  "    dst.write(header_bytes)\n", "    dst.write(header_bytes)\n    dst.write(key if returned_key else b'')\n"),
 ("M12 plaintext uploaded file kept after encrypt (no rm)", "app.py",
  "def rm(path: Optional[str]) -> None:\n        if path:", "def rm(path: Optional[str]) -> None:\n        if False:"),
 ("M13 key_from_hex accepts garbage silently", "fileenc/kdf.py",
  'raise ParameterError("key must contain only hex characters (0-9, a-f)") from None', "return b''"),
 ("M14 final tag-only chunk skipped for empty files", "fileenc/engine.py",
  "current = _read_exact(src, chunk_size)\n    while True:", "current = _read_exact(src, chunk_size)\n    if not current:\n        return returned_key\n    while True:"),
]
rows = []
for name, rel, old, new in MUTANTS:
    d = tempfile.mkdtemp()
    shutil.copytree(SRC, d + "/p", ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".coverage", "scratch_*", "*.zip"))
    path = f"{d}/p/{rel}"; s = open(path).read()
    olds, news = (old, new) if isinstance(old, list) else ([old], [new])
    ok = all(o in s for o in olds)
    if not ok:
        rows.append((name, "PATCH-NOT-APPLIED", "")); continue
    for o, n in zip(olds, news): s = s.replace(o, n)
    open(path, "w").write(s)
    try:
        r = subprocess.run("ulimit -v 6000000; python3 -m pytest -p no:cacheprovider --no-header --tb=no -rN",
                           shell=True, cwd=d + "/p", capture_output=True, text=True, timeout=240)
        txt = r.stdout.strip().splitlines(); last = txt[-1] if txt else "?"
        code = r.returncode
    except subprocess.TimeoutExpired:
        last, code = "TIMEOUT (killed)", 99
    rows.append((name, "KILLED" if code != 0 else "SURVIVED", last))
    shutil.rmtree(d, ignore_errors=True)
for n, st, last in rows: print(f"{st:17} {n}\n{'':17}   -> {last}")
print("\nkilled:", sum(1 for _, s, _ in rows if s == "KILLED"), "/", len(rows))
