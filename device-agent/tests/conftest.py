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


@pytest.fixture
def fake_download(monkeypatch):
    """
    Replaces urllib.request.urlretrieve so tests never touch the network.
    Call fake_download.set_source(path) before triggering a download to
    control what bytes get "downloaded".
    """
    state = {"source": None}

    def _urlretrieve(url, dest):
        if state["source"] is None:
            raise RuntimeError("fake_download: no source configured for this test")
        shutil.copyfile(state["source"], dest)
        return str(dest), None

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
