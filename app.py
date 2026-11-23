"""Flask front end for the FENC file encryptor. Routes only; crypto is in fileenc/.

Configuration (environment variables):
  FENC_SECRET_KEY      signs the session cookie that backs CSRF tokens
  FENC_MAX_MB          max upload size in MB            (default 100)
  FENC_MAX_CONCURRENT  simultaneous crypto operations   (default 2)
  FENC_MAX_PENDING     held raw-key downloads at once   (default 50)
  FENC_HTTPS=1         set when served over HTTPS: Secure cookies + HSTS
  FLASK_DEBUG=1        dev only; never enable on a reachable host
"""
from __future__ import annotations

import os
import secrets
import shutil
import tempfile
import threading
import time
from typing import Optional

from flask import Flask, Response, abort, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.utils import secure_filename

from fileenc import (Algorithm, AuthenticationError, FormatError,
                     ParameterError, atomic_write, decrypt_stream,
                     encrypt_stream)
from fileenc.kdf import key_from_hex, key_to_hex

ALGORITHMS = {"aes-gcm": Algorithm.AES_GCM,
              "chacha20-poly1305": Algorithm.CHACHA20_POLY1305}
MSG_AUTH = "Decryption failed: wrong key or password, or the file is corrupted."
MSG_FORMAT = "This does not look like a file made by this tool (or it is damaged)."
MSG_INTERNAL = "Something went wrong. Nothing was saved."
MSG_BUSY = "The server is busy. Please try again in a few seconds."
MSG_CSRF = "Your session expired or the request was not valid. Reload the page and try again."

# No inline scripts or styles are allowed: everything comes from /static.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def create_app(work_root: Optional[str] = None, download_ttl: int = 600,
               config: Optional[dict] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=_env_int("FENC_MAX_MB", 100) * 1024 * 1024,
        FENC_MAX_CONCURRENT=_env_int("FENC_MAX_CONCURRENT", 2),
        FENC_MAX_PENDING=_env_int("FENC_MAX_PENDING", 50),
        FENC_STALE_SECONDS=3600,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FENC_HTTPS") == "1",
        WTF_CSRF_TIME_LIMIT=3600,
    )
    secret = os.environ.get("FENC_SECRET_KEY")
    if not secret:  # never hardcoded; random per process if unset
        secret = secrets.token_hex(32)
        app.logger.warning("FENC_SECRET_KEY not set: using a random key; "
                           "sessions reset on restart and differ per worker.")
    app.config["SECRET_KEY"] = secret
    if config:
        app.config.update(config)
    CSRFProtect(app)

    root = work_root or tempfile.mkdtemp(prefix="fenc-")  # mkdtemp => mode 0700
    os.makedirs(root, mode=0o700, exist_ok=True)

    pending: dict[str, tuple[str, float, str]] = {}  # token -> (dir, expiry, name)
    lock = threading.Lock()
    slots = threading.BoundedSemaphore(app.config["FENC_MAX_CONCURRENT"])

    def rm(path: Optional[str]) -> None:
        if path:  # deletion is NOT secure erasure on SSDs / modern filesystems
            shutil.rmtree(path, ignore_errors=True)

    def sweep() -> None:
        """Delete expired downloads and orphaned work dirs (e.g. after a crash)."""
        now = time.time()
        with lock:
            for token in [t for t, (_, exp, _) in pending.items() if exp <= now]:
                rm(pending.pop(token)[0])
            live = {d for d, _, _ in pending.values()}
            stale = app.config["FENC_STALE_SECONDS"]
            for entry in os.scandir(root):
                if (entry.is_dir(follow_symlinks=False) and entry.path not in live
                        and now - entry.stat().st_mtime > stale):
                    rm(entry.path)

    @app.after_request
    def security_headers(resp: Response) -> Response:
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.endpoint != "static":
            resp.headers.setdefault("Cache-Control", "no-store")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000")
        return resp

    def page(template: str, status: int = 200, **ctx):
        return app.make_response((render_template(template, **ctx), status))

    def fail(message: str, status: int = 400):
        return page("interface.html", status, error=message)

    def busy():
        resp = fail(MSG_BUSY, 503)
        resp.headers["Retry-After"] = "5"
        return resp

    def attachment(path: str, name: str, cleanup_dir: Optional[str]):
        # NOT send_file: it sets direct_passthrough, which makes Werkzeug skip
        # Response.close(), so call_on_close cleanup would silently never run.
        def stream():
            with open(path, "rb") as f:
                while chunk := f.read(64 * 1024):
                    yield chunk

        resp = Response(stream(), mimetype="application/octet-stream")
        resp.headers.set("Content-Disposition", "attachment", filename=name)
        resp.headers["Content-Length"] = str(os.path.getsize(path))
        if cleanup_dir:  # runs when the server closes the response, even if unstarted
            resp.call_on_close(lambda: rm(cleanup_dir))
        return resp

    @app.get("/")
    def index():
        sweep()
        return page("interface.html")

    @app.post("/encrypt")
    def encrypt():
        sweep()
        upload = request.files.get("uploaded_file")
        if upload is None or not upload.filename:
            return fail("Please choose a file.")
        algorithm = ALGORITHMS.get(request.form.get("algorithm", ""))
        if algorithm is None:
            return fail("Unsupported algorithm.")
        if algorithm is Algorithm.CHACHA20_POLY1305:
            key_size = 32
        else:
            try:
                key_size = int(request.form.get("key_size", "256")) // 8
            except ValueError:
                return fail("Invalid key size.")

        password: Optional[str] = None
        mode = request.form.get("key_mode")
        if mode == "password":
            password = request.form.get("password", "")
            if password != request.form.get("password_confirm", ""):
                return fail("The two passwords do not match.")
        elif mode != "raw":
            return fail("Choose password or random key.")
        else:
            with lock:
                if len(pending) >= app.config["FENC_MAX_PENDING"]:
                    return busy()

        if not slots.acquire(blocking=False):  # bound concurrent KDF/crypto work
            return busy()
        base = secure_filename(upload.filename) or "file"
        work: Optional[str] = None
        try:
            work = tempfile.mkdtemp(dir=root)
            out_path = os.path.join(work, "out.enc")
            key = atomic_write(out_path, lambda out: encrypt_stream(
                upload.stream, out, algorithm=algorithm, key_size=key_size,
                password=password))
        except ParameterError as exc:
            rm(work)
            return fail(str(exc))
        except Exception:
            rm(work)
            app.logger.exception("encryption failed")  # tracebacks hold no secrets
            return fail(MSG_INTERNAL, 500)
        finally:
            slots.release()

        name = base + ".enc"
        if key is None:  # password mode: stream it back, then delete
            return attachment(out_path, name, work)
        # Raw-key mode: key is shown ONCE; ciphertext is held briefly for download.
        token = secrets.token_urlsafe(32)
        with lock:
            pending[token] = (work, time.time() + download_ttl, name)
        return page("result.html", key_hex=key_to_hex(key), token=token,
                    name=name, minutes=download_ttl // 60)

    @app.get("/download/<token>")
    def download(token: str):
        sweep()
        with lock:
            entry = pending.pop(token, None)  # one-time: removed before serving
        if entry is None:
            abort(404)
        work, _, name = entry
        return attachment(os.path.join(work, "out.enc"), name, work)

    @app.post("/decrypt")
    def decrypt():
        sweep()
        upload = request.files.get("uploaded_file")
        if upload is None or not upload.filename:
            return fail("Please choose an encrypted file.")
        password = request.form.get("password") or None
        key: Optional[bytes] = None
        if request.form.get("key", "").strip():
            try:
                key = key_from_hex(request.form["key"])
            except ParameterError as exc:
                return fail(str(exc))

        base = secure_filename(upload.filename)
        name = base[:-4] if base.lower().endswith(".enc") and len(base) > 4 else ""
        name = name or "decrypted_file"

        if not slots.acquire(blocking=False):
            return busy()
        work: Optional[str] = None
        try:
            work = tempfile.mkdtemp(dir=root)
            out_path = os.path.join(work, "out.dec")
            # atomic_write: out.dec exists only after the FINAL chunk authenticates
            atomic_write(out_path, lambda out: decrypt_stream(
                upload.stream, out, key=key, password=password))
        except AuthenticationError:
            rm(work)
            return fail(MSG_AUTH)
        except FormatError:
            rm(work)
            return fail(MSG_FORMAT)
        except ParameterError as exc:
            rm(work)
            return fail(str(exc))
        except Exception:
            rm(work)
            app.logger.exception("decryption failed")
            return fail(MSG_INTERNAL, 500)
        finally:
            slots.release()
        return attachment(out_path, name, work)

    @app.errorhandler(CSRFError)
    def bad_csrf(_):
        return fail(MSG_CSRF, 400)

    @app.errorhandler(413)
    def too_large(_):
        return fail("File too large (limit "
                    f"{app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB).", 413)

    @app.errorhandler(404)
    def not_found(_):
        return page("interface.html", 404, error="Not found (download links work once).")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
