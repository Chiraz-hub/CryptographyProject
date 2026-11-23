# 🔐 File Encryption Project

A small web application (and Python library) that **encrypts and decrypts files** with modern
*authenticated* encryption: **AES-GCM** and **ChaCha20-Poly1305**.

It is a learning project about file handling, applied cryptography and web security, built with
care but **not audited**. Read [Security model and limitations](#-security-model-and-limitations)
before trusting it with anything sensitive.

---

## 🚀 Features

- ✅ Encrypt **and decrypt** any file type, including empty and binary files
- ✅ AES-GCM (128 / 192 / 256-bit) and ChaCha20-Poly1305 (256-bit)
- ✅ Two key modes: a **password** you choose (scrypt) or a **random key** shown once
- ✅ Tampering, truncation and wrong keys are detected; no plaintext is released on failure
- ✅ Large files are processed in chunks (memory use does not grow with file size)
- ✅ Self-describing, versioned file format; the algorithm is read from the file, not from the form
- ✅ CSRF protection, strict Content-Security-Policy, upload size and concurrency limits
- ✅ 351 automated tests, including published test vectors

---

## 🛠️ Technologies

Python 3 · Flask · Flask-WTF (CSRF) · [`cryptography`](https://cryptography.io) · pytest

Tested with Python 3.12.3, Flask 3.1.3, Flask-WTF 1.3.0 and cryptography 46.0.6 **and** 50.0.2 (full
suite passes on both); the gunicorn instructions were checked with gunicorn 26.2.0. The versions in
`requirements.txt` are lower bounds that I have **not** tested individually.

---

## ⚡ Quick start

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Sign the session cookie that backs CSRF tokens (keep it out of git)
export FENC_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

flask --app app run
```

Open <http://127.0.0.1:5000>. Without `FENC_SECRET_KEY` the app still runs, using a random key
that changes on every restart.

> `crypt.py` was renamed to `app.py` because `crypt` is also the name of a (removed) standard-library module.

---

## 🖥️ Using the web app

**Encrypt**

1. Choose an algorithm (AES-GCM is the default) and, for AES, a key size.
2. Choose how to protect the file:
   - **A password I choose** (minimum 12 characters, entered twice). You get the `.enc` file back immediately.
   - **A random key (shown once).** The key appears on a results page and is **not stored anywhere**. Copy it, then download the `.enc` file. The download link works once and expires after 10 minutes.
3. Select the file and press *Encrypt*.

**Decrypt**

1. Select the `.enc` file.
2. Enter the password **or** paste the hex key, whichever you used. The algorithm and parameters are read from the file itself.
3. On success the original file downloads. On any failure you get one generic message and nothing is produced.

---

## 🐍 Using it as a Python library

```python
from fileenc import Algorithm, encrypt_file, decrypt_file

# Password mode: the key is derived with scrypt; nothing secret is returned.
encrypt_file("report.pdf", "report.pdf.enc", password="a long passphrase here")
decrypt_file("report.pdf.enc", "report.restored.pdf", password="a long passphrase here")

# Random-key mode: the key is RETURNED and never written into the file.
key = encrypt_file("report.pdf", "report2.pdf.enc")      # AES-256-GCM by default
decrypt_file("report2.pdf.enc", "report2.restored.pdf", key=key)
print(key.hex())   # store this safely, separately from the .enc file

# ChaCha20-Poly1305 instead of AES-GCM
encrypt_file("report.pdf", "report3.pdf.enc",
             algorithm=Algorithm.CHACHA20_POLY1305, key_size=32)
```

Failures are reported with specific exceptions:

```python
from fileenc import AuthenticationError, FormatError, ParameterError, decrypt_file

try:
    decrypt_file("report.pdf.enc", "out.pdf", password="wrong password!!")
except AuthenticationError:
    print("Wrong key or password, or the file was modified.")   # no out.pdf is created
except FormatError:
    print("Not a file made by this tool.")
except ParameterError as exc:
    print("Bad input:", exc)
```

Both functions refuse to overwrite an existing file (pass `overwrite=True` to allow it), refuse
`destination == source`, write to a temporary file first, and rename it atomically only on
complete success.

---

## 🔑 Algorithms

| Algorithm | Key sizes | Status |
|---|---|---|
| **AES-GCM** | 128 / 192 / 256 bits | Recommended. Authenticated. Hardware-accelerated on most CPUs. Default: 256. |
| **ChaCha20-Poly1305** | 256 bits (fixed) | Recommended. Authenticated. Fast without AES hardware. |

**Removed from the old version, on purpose:**

| Old option | Why it is gone |
|---|---|
| DES | 56-bit effective key; brute-forceable. (Also did not work with current `cryptography`.) |
| RC4 | Broken keystream biases; no nonce. |
| Blowfish-CBC | 64-bit blocks (Sweet32-style collisions on large data); deprecated upstream. |
| AES-CBC, raw ChaCha20 | Work mechanically, but have **no authentication**: modified ciphertext goes undetected. |

Neither remaining algorithm is "secure" just because of its name. Security depends on key or
password strength, on never losing control of the key, and on the environment the app runs in.

---

## 🧾 File format (FENC v1)

A single `.enc` file: a 38-byte header, then ciphertext chunks. The header is **not secret** and
contains no key or password.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `FENC` |
| 4 | 1 | Format version (`1`) |
| 5 | 1 | Algorithm (`1` AES-GCM, `2` ChaCha20-Poly1305) |
| 6 | 1 | Key mode (`1` raw key, `2` password) |
| 7 | 1 | Key length in bytes (16, 24 or 32) |
| 8 | 4 | Chunk size (big-endian; default 64 KiB) |
| 12 | 7 | Random nonce prefix |
| 19 | 16 | scrypt salt (zeros in raw-key mode) |
| 35 | 1 | scrypt log2(N) (default 15) |
| 36 | 1 | scrypt r (default 8) |
| 37 | 1 | scrypt p (default 1) |
| 38 | … | Chunks: ciphertext + 16-byte tag each |

How it stays safe:

- **Per-chunk nonce** = 7-byte random prefix + 4-byte counter + 1-byte "final chunk" flag. Nonces never repeat within a file.
- **The whole header is authenticated** (as associated data) on every chunk, so changing any header byte makes decryption fail.
- **The final-chunk flag** makes truncation detectable, even when the file is cut exactly at a chunk boundary. Empty files are a single, tag-only final chunk.
- **The decryptor bounds the scrypt parameters** it reads from the file (memory cap 128 MiB), so a hostile file cannot make the server allocate gigabytes.
- The original filename is **not stored** (it would leak metadata). Decryption strips `.enc` from the uploaded name, or uses `decrypted_file`.

---

## 🗝️ Key management

- **Password mode:** the key is derived with **scrypt** (N=2¹⁵, r=8, p=1, fresh 16-byte salt per file). A plain hash of the password is never used. The password is only as strong as you make it: prefer a long random passphrase (for example five or six random words) over a short "complex" one, and keep it in a password manager. The 12-character minimum is a floor, not a recommendation.
- **Random-key mode:** the key is generated by the operating system's CSPRNG and shown **once** (64 hex characters for a 256-bit key). Store it **separately** from the `.enc` file. Storing both together defeats the purpose, which was the main flaw of the old version's zip file.
- **Hex is an encoding, not protection.** Anyone who sees the hex string has the key.
- **There is no recovery.** If you lose the password or key, the data is gone. There is no backdoor, reset, or "forgot password". Back up keys before deleting originals, and verify that you can decrypt a test copy first.

---

## 🛡️ Security model and limitations

**What it is designed to do:** protect file contents against someone who obtains only the `.enc` file, and detect any modification of it.

**What it does *not* do:**

- **The server sees your plaintext and password while it works.** Encryption happens on the server, not in your browser. Run it yourself, or only on a server you trust. A hosted copy run by someone else could read everything. Truly private file encryption would be done client-side.
- **No HTTPS by itself.** Without TLS, passwords and files travel in cleartext. Terminate TLS in front of the app (see below).
- **File sizes, the algorithm and key size are visible** in the encrypted file. Contents are not.
- **Deleting temporary files is not secure erasure.** On SSDs and modern filesystems, deleted data can persist. The web server may also spool large uploads to the system temp directory.
- **No per-user accounts and no per-IP rate limiting.** Concurrency and pending-download caps prevent memory and disk exhaustion, but one client can still occupy the available slots.
- **This code has not been independently audited.**

Built-in protections: CSRF tokens; a Content-Security-Policy that forbids inline scripts; `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`; a 100 MB default upload cap; sanitised filenames (no path traversal); generic error messages; and logs that never contain passwords or keys.

---

## ⚙️ Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `FENC_SECRET_KEY` | random per start | Signs the session cookie that backs CSRF tokens. Set it in production. |
| `FENC_MAX_MB` | `100` | Maximum upload size, in MB. |
| `FENC_MAX_CONCURRENT` | `2` | Simultaneous encrypt/decrypt operations; extra requests get HTTP 503. |
| `FENC_MAX_PENDING` | `50` | Random-key downloads held at once (10-minute expiry). |
| `FENC_HTTPS` | unset | Set to `1` when served over HTTPS: enables `Secure` cookies and HSTS. |
| `FLASK_DEBUG` | unset | `1` enables the debugger. **Development only; never on a reachable host.** |

---

## 🌐 Deployment notes

`flask run` is a development server. For anything beyond local use:

```bash
pip install gunicorn
export FENC_SECRET_KEY=...        # a long random value, kept out of source control
export FENC_HTTPS=1               # only once TLS is in place
gunicorn --workers 1 --threads 4 --timeout 120 --bind 127.0.0.1:8000 app:app
```

- **Use exactly one worker process.** Pending random-key downloads and the concurrency limiter live in process memory. With several worker processes, a download link may hit a different worker and return 404, and the limits are no longer shared. Scale with threads, or move that state to shared storage first.
- Put it behind a **reverse proxy that terminates TLS** (nginx, Caddy, ...) and sets its own body-size limit to match `FENC_MAX_MB`.
- Raise `--timeout` if you expect large files; scrypt and big uploads take time.

---

## ✅ Testing

```bash
pip install -r requirements-dev.txt
pytest                                                        # 351 tests, ~15 s
pytest --cov=fileenc --cov=app --cov-report=term-missing      # coverage
python tests/mutation_check.py                                # optional; needs a POSIX shell
```

The suite includes the RFC 8439 (ChaCha20-Poly1305), McGrew-Viega (AES-GCM) and RFC 7914 (scrypt) test vectors; an independent reference implementation of the file format (`tests/reference.py`); "golden" files that keep format v1 decryptable forever; bit-flips at every byte offset; truncation at every length; and a memory-bound test on 24 MiB streams. `mutation_check.py` deliberately breaks the code in 15 ways and confirms the suite notices each one.

---

## 📁 Project structure

```
app.py                  Flask routes, CSRF, headers, limits (no cryptography here)
fileenc/
    header.py           FENC v1 header: pack, strict parse, validation, scrypt bounds
    kdf.py              random keys, scrypt derivation, hex key helpers
    engine.py           chunked encrypt/decrypt, atomic_write, encrypt_file/decrypt_file
    errors.py           FileEncError, ParameterError, FormatError, AuthenticationError
templates/              interface.html (encrypt + decrypt), result.html (key shown once)
static/                 styles.css, app.js (no inline scripts: required by the CSP)
tests/                  pytest suite and the independent reference implementation
```

---

## 📦 Migrating files from the old version

Files from the original version (the `*_encrypted.zip` containing `.enc`, `.key` and `.iv`) have **no header**, so this app rejects them and never guesses. Only the AES-CBC option of the old version is described here. If you used DES, RC4, Blowfish or ChaCha20, ask for help, since those are not covered.

```python
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_legacy_aes_cbc(enc_path, key_path, iv_path, out_path):
    key = open(key_path, "rb").read()
    iv = open(iv_path, "rb").read()
    data = open(enc_path, "rb").read()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    open(out_path, "wb").write(unpadder.update(padded) + unpadder.finalize())
```

Then re-encrypt the recovered file with `encrypt_file(...)`. The old format was unauthenticated: a wrong key or damaged file may produce garbage or a padding error, not a clean failure. If your old `uploads/` folder ever held real files or keys, delete them and check whether they were committed to git (history keeps them even after deletion).

---

## 🩺 Troubleshooting

| Message | Cause |
|---|---|
| "Your session expired or the request was not valid" | The page was open for over an hour, or cookies are blocked. Reload and retry. |
| "The server is busy" (503) | All crypto slots or pending-download slots are in use. Retry in a few seconds. |
| "File too large" (413) | Over `FENC_MAX_MB`. |
| "Decryption failed: wrong key or password, or the file is corrupted" | Deliberately vague: a wrong secret and a modified file are indistinguishable by design. |
| "This does not look like a file made by this tool" | Not a FENC v1 file (for example, one from the old version). |

---

Author:  
Boucenna Chiraz  
Computer Science Student — Learning Cryptography & Web Security
