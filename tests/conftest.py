import io
import itertools
import os
import re

import pytest

from app import create_app

TOKEN_RE = re.compile(rb'name="csrf_token" value="([^"]+)"')


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch):
    for name in [k for k in os.environ if k.startswith("FENC_")] + ["FLASK_DEBUG"]:
        monkeypatch.delenv(name, raising=False)


class Rig:
    """A fresh app + browser session + isolated work root. CSRF is ENABLED."""

    def __init__(self, root, ttl=600, **config):
        root.mkdir()
        self.root = root
        self.app = create_app(work_root=str(root), download_ttl=ttl, config=config or None)
        self.client = self.app.test_client()

    def token(self, client=None) -> str:
        return TOKEN_RE.search((client or self.client).get("/").data).group(1).decode()

    def post(self, path, fields=None, content=b"hello", fname="a.txt",
             token="auto", client=None, filefield="uploaded_file"):
        cl = client or self.client
        data = dict(fields or {})
        if token == "auto":
            token = self.token(cl)
        if token is not None:
            data["csrf_token"] = token
        if filefield:
            data[filefield] = (io.BytesIO(content), fname)
        resp = cl.post(path, data=data, content_type="multipart/form-data")
        body = resp.data
        resp.close()          # fires call_on_close cleanup, like a real server would
        return resp, body

    def get(self, path, client=None):
        resp = (client or self.client).get(path)
        body = resp.data
        resp.close()
        return resp, body

    def leftovers(self):
        return sorted(os.listdir(self.root))


@pytest.fixture
def make_rig(tmp_path):
    counter = itertools.count()
    return lambda **kw: Rig(tmp_path / f"rig{next(counter)}", **kw)


@pytest.fixture
def rig(make_rig):
    return make_rig()
