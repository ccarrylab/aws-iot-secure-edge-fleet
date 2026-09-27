import io
import shutil
import sys
from pathlib import Path

import pytest

# ota_handler.py lives one directory up from tests/ — make sure it's importable
# regardless of how pytest was invoked.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ota_handler as ota_handler_module  # noqa: E402


@pytest.fixture
def isolated_cwd(tmp_path, monkeypatch):
    """
    ota_handler.py's PACKAGES_DIR / CURRENT_LINK / STATE_FILE are module-level
    relative Paths. Relative Paths resolve against the process cwd at the time
    of each filesystem call, so chdir'ing into a fresh tmp_path per test is
    enough to fully isolate tests from each other and from the real repo —
    no monkeypatching of the constants themselves required.
    """
    monkeypatch.chdir(tmp_path)
    return tmp_path


class _FakeResponse:
    """Stands in for the object returned by urllib.request.urlopen, which is
    what ota_handler._download() streams from."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)
        self.headers = {"Content-Length": str(len(data))}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def fake_download(monkeypatch):
    """
    Replaces the network entry points so tests never touch the network.
    Call fake_download.set_source(path) before triggering a download to
    control what bytes get "downloaded".

    Both urlopen (used by the hardened _download, which streams so it can
    enforce a size cap and write via a .part file) and urlretrieve (the
    original call) are patched, so tests written against either shape work.
    """
    state = {"source": None}

    def _payload() -> bytes:
        if state["source"] is None:
            raise RuntimeError("fake_download: no source configured for this test")
        return Path(state["source"]).read_bytes()

    def _urlopen(url, timeout=None, **kwargs):
        return _FakeResponse(_payload())

    def _urlretrieve(url, dest, *args, **kwargs):
        Path(dest).write_bytes(_payload())
        return str(dest), None

    monkeypatch.setattr(
        ota_handler_module.urllib.request, "urlopen", _urlopen
    )
    monkeypatch.setattr(
        ota_handler_module.urllib.request, "urlretrieve", _urlretrieve
    )

    class Controller:
        def set_source(self, path):
            state["source"] = path

    return Controller()


@pytest.fixture
def status_log():
    """Captures every on_status(status, detail) call an OTAHandler makes."""
    calls = []

    def _on_status(status, detail):
        calls.append((status, detail))

    _on_status.calls = calls
    return _on_status
