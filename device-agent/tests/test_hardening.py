"""
Tests for the hardening changes in ota_handler.py.

These are the negative cases that did not exist before: each one exercises a
specific way a malicious or malformed OTA job document could previously cause
the device to do something it should never do.
"""

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from ota_handler import (
    CURRENT_LINK,
    OTAHandler,
    PACKAGES_DIR,
    STATE_FILE,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_tarball(files: dict, name: str = "pkg.tar.gz") -> Path:
    """Build a gzipped tarball containing {path: text}."""
    p = Path(name)
    with tarfile.open(p, "w:gz") as tar:
        for member_name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=member_name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return p


def raw_member_tarball(info: tarfile.TarInfo, fileobj, name: str = "evil.tar.gz") -> Path:
    """Build a tarball from a single hand-crafted TarInfo."""
    p = Path(name)
    with tarfile.open(p, "w:gz") as tar:
        tar.addfile(info, fileobj)
    return p


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def job(version="1.2.0", url="https://example.com/pkg.tar.gz", checksum=None, **extra):
    doc = {"version": version, "packageUrl": url, "checksum": checksum or ("a" * 64)}
    doc.update(extra)
    return doc


# ---------------------------------------------------------------------------
# C1 - the version identifier is never a path component
# ---------------------------------------------------------------------------

class TestVersionValidation:
    @pytest.mark.parametrize(
        "bad_version",
        ["../../outside", "..", "../", "a/b", "/etc", "1.0.0/../../x", "", ".hidden", "a" * 64],
    )
    def test_traversal_versions_are_refused_in_handle_job(
        self, isolated_cwd, status_log, bad_version
    ):
        handler = OTAHandler(on_status=status_log)
        assert handler.handle_job(job(version=bad_version)) is False
        assert status_log.calls[-1][0] == "FAILED"

    def test_traversal_version_refused_in_extract_directly(self, isolated_cwd):
        handler = OTAHandler()
        archive = make_tarball({"app.py": "x"})
        with pytest.raises(ValueError, match="unsafe version"):
            handler._extract(archive, "../../etc")

    def test_ordinary_versions_are_still_accepted(self, isolated_cwd):
        handler = OTAHandler()
        for good in ("1.2.0", "1.2.0-rc1", "v2.0.0_build.7", "2026.09.27"):
            handler._extract(make_tarball({"app.py": "x"}, "g.tar.gz"), good)
            assert (PACKAGES_DIR / good).exists()


# ---------------------------------------------------------------------------
# C2 - archive containment and link members
# ---------------------------------------------------------------------------

class TestArchiveHardening:
    def test_prefix_sibling_escape_is_rejected(self, isolated_cwd):
        """
        The old guard was str(member_path).startswith(str(install_dir)) — a
        PREFIX match, so a sibling directory called "1.0.0evil" passed a check
        meant to reject escapes.
        """
        handler = OTAHandler()
        (PACKAGES_DIR / "1.0.0evil").mkdir(parents=True)

        info = tarfile.TarInfo(name="../1.0.0evil/planted.txt")
        info.size = 3
        archive = raw_member_tarball(info, io.BytesIO(b"pwn"))

        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler._extract(archive, "1.0.0")

        assert not (PACKAGES_DIR / "1.0.0evil" / "planted.txt").exists()

    def test_device_node_member_is_rejected(self, isolated_cwd):
        handler = OTAHandler()
        info = tarfile.TarInfo(name="null")
        info.type = tarfile.CHRTYPE
        archive = raw_member_tarball(info, io.BytesIO(b""))
        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler._extract(archive, "1.0.0")

    def test_archive_with_too_many_members_is_rejected(self, isolated_cwd):
        handler = OTAHandler()
        p = Path("many.tar.gz")
        with tarfile.open(p, "w:gz") as tar:
            for i in range(6000):
                info = tarfile.TarInfo(name="f%d" % i)
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler._extract(p, "1.0.0")

    def test_corrupt_archive_does_not_destroy_the_existing_copy(self, isolated_cwd):
        """
        Extraction is staged: a bad archive must not take out the copy that is
        already installed (which is exactly what a rollback falls back to).
        """
        handler = OTAHandler()
        handler._extract(make_tarball({"app.py": "known-good"}, "good.tar.gz"), "1.0.0")

        bad = Path("corrupt.tar.gz")
        bad.write_bytes(b"not a gzip stream at all")

        with pytest.raises(Exception):
            handler._extract(bad, "1.0.0")

        assert (PACKAGES_DIR / "1.0.0" / "app.py").read_text() == "known-good"

    def test_no_staging_directory_is_left_behind(self, isolated_cwd):
        handler = OTAHandler()
        handler._extract(make_tarball({"app.py": "x"}, "s.tar.gz"), "1.2.0")
        assert not [p for p in PACKAGES_DIR.iterdir() if p.name.startswith(".staging-")]


# ---------------------------------------------------------------------------
# C3 - the checksum is required, not optional
# ---------------------------------------------------------------------------

class TestChecksumRequired:
    def test_missing_checksum_fails_the_update(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        """Replaces the old test_missing_checksum_skips_verification_entirely,
        which documented the fail-open behaviour. It must now REFUSE."""
        archive = make_tarball({"app.py": "print('unverified')"}, "nc.tar.gz")
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        assert handler.handle_job(
            {"version": "1.2.0", "packageUrl": "https://example.com/pkg.tar.gz"}
        ) is False
        assert status_log.calls[-1][0] == "FAILED"
        assert not CURRENT_LINK.exists(), "nothing should have been activated"

    def test_malformed_checksum_fails(self, isolated_cwd, status_log):
        handler = OTAHandler(on_status=status_log)
        assert handler.handle_job(job(checksum="not-a-digest")) is False
        assert handler.handle_job(job(checksum="abc123")) is False
        assert handler.handle_job(job(checksum="g" * 64)) is False

    def test_uppercase_checksum_is_still_accepted(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        archive = make_tarball({"app.py": "print('hi')"}, "uc.tar.gz")
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)
        assert handler.handle_job(job(checksum=sha256_of(archive).upper())) is True


# ---------------------------------------------------------------------------
# H4 - transport hardening
# ---------------------------------------------------------------------------

class TestTransport:
    def test_plain_http_package_url_is_refused(self, isolated_cwd, status_log):
        handler = OTAHandler(on_status=status_log)
        assert handler.handle_job(job(url="http://example.com/pkg.tar.gz")) is False
        assert "non-HTTPS" in status_log.calls[-1][1]["error"]

    def test_download_rejects_oversized_content_length(
        self, isolated_cwd, fake_download, monkeypatch
    ):
        import ota_handler as mod

        archive = make_tarball({"app.py": "x"}, "big.tar.gz")
        fake_download.set_source(archive)
        monkeypatch.setattr(mod, "MAX_DOWNLOAD_BYTES", 10)

        handler = OTAHandler()
        with pytest.raises(RuntimeError, match="too large"):
            handler._download("https://example.com/big.tar.gz", "1.2.0")

    def test_partial_download_file_is_not_left_behind(self, isolated_cwd, fake_download):
        archive = make_tarball({"app.py": "x"}, "p.tar.gz")
        fake_download.set_source(archive)
        handler = OTAHandler()
        assert handler._download("https://example.com/p.tar.gz", "1.2.0").exists()
        assert not (PACKAGES_DIR / "1.2.0.tar.gz.part").exists()


# ---------------------------------------------------------------------------
# H1 - activation is atomic
# ---------------------------------------------------------------------------

class TestAtomicActivation:
    def test_current_is_never_absent_between_activations(self, isolated_cwd):
        handler = OTAHandler()
        for version in ("1.0.0", "1.1.0"):
            (PACKAGES_DIR / version).mkdir(parents=True, exist_ok=True)
            (PACKAGES_DIR / version / "app.py").write_text(version)

        handler._activate("1.0.0")
        assert CURRENT_LINK.is_symlink()
        assert CURRENT_LINK.resolve().name == "1.0.0"

        handler._activate("1.1.0")
        assert CURRENT_LINK.is_symlink()
        assert CURRENT_LINK.resolve().name == "1.1.0"
        assert not (PACKAGES_DIR / "current.tmp").exists()

    def test_activating_a_missing_version_is_refused(self, isolated_cwd):
        handler = OTAHandler()
        with pytest.raises(RuntimeError, match="does not exist"):
            handler._activate("9.9.9")
        assert not CURRENT_LINK.exists()

    def test_state_file_is_written_atomically(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True, exist_ok=True)
        (PACKAGES_DIR / "1.2.0" / "app.py").write_text("x")
        handler._save_state("1.2.0", checksum="b" * 64)

        data = json.loads(STATE_FILE.read_text())
        assert data["version"] == "1.2.0"
        assert data["checksum"] == "b" * 64
        assert not (PACKAGES_DIR / "state.json.tmp").exists()

    def test_corrupt_state_file_is_reported_not_swallowed(self, isolated_cwd, capsys):
        handler = OTAHandler()
        PACKAGES_DIR.mkdir(exist_ok=True)
        STATE_FILE.write_text("{ this is not json")
        assert handler._get_current_version() is None
        assert "unreadable state file" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# C5 - the default health check can actually fail
# ---------------------------------------------------------------------------

class TestHealthCheck:
    def test_no_current_release_fails(self, isolated_cwd):
        assert OTAHandler()._health_check() is False

    def test_empty_payload_fails(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.0.0").mkdir(parents=True, exist_ok=True)
        os.symlink((PACKAGES_DIR / "1.0.0").resolve(), CURRENT_LINK)
        assert handler._health_check() is False

    def test_real_payload_passes(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.0.0").mkdir(parents=True, exist_ok=True)
        os.symlink((PACKAGES_DIR / "1.0.0").resolve(), CURRENT_LINK)
        (PACKAGES_DIR / "1.0.0" / "app.py").write_text("x")
        assert handler._health_check() is True

    def test_explicit_health_check_command_still_honoured(self, isolated_cwd):
        handler = OTAHandler(health_check_cmd=["true"])
        assert handler._health_check() is True
        handler = OTAHandler(health_check_cmd=["false"])
        assert handler._health_check() is False


# ---------------------------------------------------------------------------
# G - overwriting the running release
# ---------------------------------------------------------------------------

class TestReinstallGuard:
    def test_reinstalling_the_active_version_is_refused(
        self, isolated_cwd, fake_download, status_log
    ):
        archive = make_tarball({"app.py": "print('v1')"}, "r1.tar.gz")
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)
        doc = job(checksum=sha256_of(archive))

        assert handler.handle_job(doc) is True
        assert handler.handle_job(doc) is False
        assert "already installed" in status_log.calls[-1][1]["error"]

    def test_force_reinstall_is_honoured(
        self, isolated_cwd, fake_download, status_log
    ):
        archive = make_tarball({"app.py": "print('v1')"}, "r2.tar.gz")
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log, allow_reinstall=True)
        doc = job(checksum=sha256_of(archive))
        assert handler.handle_job(doc) is True
        assert handler.handle_job(doc) is True

# ---------------------------------------------------------------------------
# Import hygiene - catch a stray ota_handler.py shadowing the repo copy
# ---------------------------------------------------------------------------

class TestImportHygiene:
    def test_ota_handler_under_test_is_the_repo_copy(self):
        """
        A loose copy of ota_handler.py in a parent directory (e.g. ~/Downloads)
        can shadow the repo module, because pytest puts conftest directories on
        sys.path. That produced five confusing behavioural failures instead of
        one clear one, so this test makes the cause self-diagnosing.
        """
        import ota_handler as mod

        module = Path(mod.__file__).resolve()
        package_root = Path(__file__).resolve().parent.parent
        assert module.parent == package_root, (
            "ota_handler was imported from %s instead of %s - move or delete "
            "the stray copy." % (module, package_root)
        )
