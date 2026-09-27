"""
Tests for device-agent/ota_handler.py.

Run from device-agent/:
    pytest

Every test that touches the filesystem uses the `isolated_cwd` fixture,
which chdirs into a fresh tmp_path so OTAHandler's module-level
PACKAGES_DIR / CURRENT_LINK / STATE_FILE never collide across tests or
touch the real repo.
"""

import hashlib
import io
import json
import tarfile
import time
from pathlib import Path

import pytest

from ota_handler import OTAHandler, PACKAGES_DIR, CURRENT_LINK, STATE_FILE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_tarball(tmp_path: Path, files: dict, name: str = "package.tar.gz") -> Path:
    """Build a small tar.gz with the given {relative_path: content} files."""
    archive_path = tmp_path / name
    with tarfile.open(archive_path, "w:gz") as tar:
        for rel_path, content in files.items():
            src = tmp_path / "src" / rel_path
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text(content)
            tar.add(src, arcname=rel_path)
    return archive_path


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add_raw_member(archive_path: Path, member: tarfile.TarInfo, fileobj=None):
    """Append a hand-built TarInfo (used for malicious-archive tests)."""
    mode = "a:gz" if archive_path.exists() else "w:gz"
    # tarfile can't append to gzip streams — rebuild instead.
    existing = []
    if archive_path.exists():
        with tarfile.open(archive_path, "r:gz") as tar:
            existing = [(m, tar.extractfile(m)) for m in tar.getmembers()]
    with tarfile.open(archive_path, "w:gz") as tar:
        for m, f in existing:
            tar.addfile(m, f)
        tar.addfile(member, fileobj)


def extracted_version_dir(version: str) -> Path:
    return PACKAGES_DIR / version


# ---------------------------------------------------------------------------
# Checksum verification
# ---------------------------------------------------------------------------

class TestVerifyChecksum:
    def test_matching_checksum_passes(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = make_tarball(tmp_path, {"app.py": "print('hi')"})
        assert handler._verify_checksum(archive, sha256_of(archive)) is True

    def test_mismatched_checksum_fails(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = make_tarball(tmp_path, {"app.py": "print('hi')"})
        assert handler._verify_checksum(archive, "0" * 64) is False

    def test_tampered_file_fails(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = make_tarball(tmp_path, {"app.py": "print('hi')"})
        expected = sha256_of(archive)
        archive.write_bytes(archive.read_bytes() + b"tampered")
        assert handler._verify_checksum(archive, expected) is False

    def test_uppercase_expected_checksum_still_matches_in_handle_job(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        """
        handle_job() lowercases the checksum from the job document before
        comparing, so a checksum supplied in uppercase should still verify.
        _verify_checksum itself does a plain string compare, so this needs
        to go through handle_job to exercise the lowercasing.
        """
        archive = make_tarball(tmp_path, {"app.py": "print('hi')"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        job = {
            "version": "1.0.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": sha256_of(archive).upper(),
        }
        assert handler.handle_job(job) is True


# ---------------------------------------------------------------------------
# Extract / path-traversal guarding
# ---------------------------------------------------------------------------

class TestExtract:
    def test_normal_archive_extracts_cleanly(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = make_tarball(tmp_path, {"app.py": "print('ok')", "lib/util.py": "x=1"})
        install_dir = handler._extract(archive, "1.2.0")
        assert (install_dir / "app.py").exists()
        assert (install_dir / "lib" / "util.py").exists()

    def test_re_extracting_same_version_replaces_old_contents(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive_v1 = make_tarball(tmp_path, {"app.py": "print('v1')"}, name="v1.tar.gz")
        handler._extract(archive_v1, "1.2.0")

        archive_v2 = make_tarball(tmp_path, {"app.py": "print('v2')"}, name="v2.tar.gz")
        install_dir = handler._extract(archive_v2, "1.2.0")

        assert (install_dir / "app.py").read_text() == "print('v2')"

    def test_rejects_absolute_path_member(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = tmp_path / "evil_absolute.tar.gz"
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 4
        add_raw_member(archive, info, io.BytesIO(b"root"))

        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler._extract(archive, "1.2.0")

    def test_rejects_dot_dot_traversal_member(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = tmp_path / "evil_dotdot.tar.gz"
        info = tarfile.TarInfo(name="../../outside.txt")
        info.size = 4
        add_raw_member(archive, info, io.BytesIO(b"root"))

        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler._extract(archive, "1.2.0")

        assert not (PACKAGES_DIR.parent.parent / "outside.txt").exists()

    @pytest.mark.xfail(
        reason=(
            "_extract only validates member.name against install_dir, not the "
            "*target* of symlink members. A symlink whose own name is safe "
            "(e.g. 'escape') but whose linkname points outside install_dir "
            "(e.g. '/etc') is currently extracted without error. Fix _extract "
            "to also validate SYMTYPE/LNKTYPE member.linkname, then remove "
            "this xfail."
        ),
        strict=True,
    )
    def test_rejects_symlink_member_escaping_install_dir(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        archive = tmp_path / "evil_symlink.tar.gz"
        info = tarfile.TarInfo(name="escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc"
        add_raw_member(archive, info)

        with pytest.raises(RuntimeError, match="Unsafe path"):
            handler._extract(archive, "1.2.0")


# ---------------------------------------------------------------------------
# Activate
# ---------------------------------------------------------------------------

class TestActivate:
    def test_activate_points_current_at_new_version(self, isolated_cwd, tmp_path):
        handler = OTAHandler()
        make_tarball(tmp_path, {"app.py": "1"})
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)

        handler._activate("1.2.0")

        assert CURRENT_LINK.is_symlink()
        assert CURRENT_LINK.resolve() == (PACKAGES_DIR / "1.2.0").resolve()

    def test_activate_overwrites_existing_symlink(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.1.0").mkdir(parents=True)
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)

        handler._activate("1.1.0")
        assert CURRENT_LINK.resolve() == (PACKAGES_DIR / "1.1.0").resolve()

        handler._activate("1.2.0")
        assert CURRENT_LINK.resolve() == (PACKAGES_DIR / "1.2.0").resolve()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class TestHealthCheck:
    def test_default_check_fails_when_current_link_missing(self, isolated_cwd):
        handler = OTAHandler()
        assert handler._health_check() is False

    def test_default_check_fails_when_version_dir_empty(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)
        handler._activate("1.2.0")
        assert handler._health_check() is False

    def test_default_check_passes_when_version_dir_nonempty(self, isolated_cwd):
        handler = OTAHandler()
        version_dir = PACKAGES_DIR / "1.2.0"
        version_dir.mkdir(parents=True)
        (version_dir / "app.py").write_text("print(1)")
        handler._activate("1.2.0")
        assert handler._health_check() is True

    def test_custom_command_success(self, isolated_cwd):
        handler = OTAHandler(health_check_cmd=["true"])
        assert handler._health_check() is True

    def test_custom_command_failure(self, isolated_cwd):
        handler = OTAHandler(health_check_cmd=["false"])
        assert handler._health_check() is False

    def test_custom_command_timeout_counts_as_failure(self, isolated_cwd):
        handler = OTAHandler(
            health_check_cmd=["python3", "-c", "import time; time.sleep(5)"],
            health_check_timeout=1,
        )
        assert handler._health_check() is False

    def test_custom_command_nonexistent_binary_counts_as_failure(self, isolated_cwd):
        handler = OTAHandler(health_check_cmd=["/no/such/binary-xyz"])
        assert handler._health_check() is False


# ---------------------------------------------------------------------------
# Rollback / state
# ---------------------------------------------------------------------------

class TestRollbackAndState:
    def test_rollback_to_existing_version_succeeds(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.1.0").mkdir(parents=True)
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)
        handler._activate("1.2.0")

        assert handler._rollback("1.1.0") is True
        assert CURRENT_LINK.resolve() == (PACKAGES_DIR / "1.1.0").resolve()
        assert json.loads(STATE_FILE.read_text())["version"] == "1.1.0"

    def test_rollback_to_missing_version_returns_false_without_raising(self, isolated_cwd):
        handler = OTAHandler()
        assert handler._rollback("9.9.9") is False

    def test_get_current_version_prefers_state_file(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)
        handler._activate("1.2.0")
        handler._save_state("1.2.0")
        assert handler._get_current_version() == "1.2.0"

    def test_get_current_version_falls_back_to_symlink_when_state_missing(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)
        handler._activate("1.2.0")
        assert not STATE_FILE.exists()
        assert handler._get_current_version() == "1.2.0"

    def test_get_current_version_falls_back_when_state_file_corrupt(self, isolated_cwd):
        handler = OTAHandler()
        (PACKAGES_DIR / "1.2.0").mkdir(parents=True)
        handler._activate("1.2.0")
        STATE_FILE.write_text("{not valid json")
        assert handler._get_current_version() == "1.2.0"

    def test_get_current_version_none_when_nothing_installed(self, isolated_cwd):
        handler = OTAHandler()
        assert handler._get_current_version() is None


# ---------------------------------------------------------------------------
# handle_job — end to end
# ---------------------------------------------------------------------------

class TestHandleJob:
    def test_missing_version_fails_without_raising(self, isolated_cwd, status_log):
        handler = OTAHandler(on_status=status_log)
        ok = handler.handle_job({"packageUrl": "https://example.com/pkg.tar.gz"})
        assert ok is False
        assert status_log.calls[-1][0] == "FAILED"

    def test_missing_package_url_fails_without_raising(self, isolated_cwd, status_log):
        handler = OTAHandler(on_status=status_log)
        ok = handler.handle_job({"version": "1.2.0"})
        assert ok is False
        assert status_log.calls[-1][0] == "FAILED"

    def test_happy_path_reports_succeeded_and_activates(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        archive = make_tarball(tmp_path, {"app.py": "print('good build')"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        job = {
            "version": "1.2.0",
            "packageUrl": "https://example.com/releases/app-1.2.0.tar.gz",
            "checksum": sha256_of(archive),
        }

        assert handler.handle_job(job) is True
        assert CURRENT_LINK.resolve() == (PACKAGES_DIR / "1.2.0").resolve()
        assert (CURRENT_LINK / "app.py").read_text() == "print('good build')"
        assert json.loads(STATE_FILE.read_text())["version"] == "1.2.0"
        assert status_log.calls[-1][0] == "SUCCEEDED"

    def test_downloaded_tarball_is_cleaned_up_on_success(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        archive = make_tarball(tmp_path, {"app.py": "print(1)"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        handler.handle_job({
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": sha256_of(archive),
        })

        assert not (PACKAGES_DIR / "1.2.0.tar.gz").exists()

    def test_downloaded_tarball_is_cleaned_up_on_failure(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        archive = make_tarball(tmp_path, {"app.py": "print(1)"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        handler.handle_job({
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": "0" * 64,  # forces a checksum-mismatch failure
        })

        assert not (PACKAGES_DIR / "1.2.0.tar.gz").exists()

    def test_missing_checksum_skips_verification_entirely(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        """
        Documents current behavior: handle_job only verifies the checksum
        `if checksum and not self._verify_checksum(...)`. A job document
        with no checksum field skips verification and still succeeds.
        Consider making the checksum field required — a job with a missing
        or empty checksum should probably fail closed, not open.
        """
        archive = make_tarball(tmp_path, {"app.py": "print('unverified')"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        job = {
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            # no "checksum" key at all
        }

        assert handler.handle_job(job) is True

    def test_checksum_mismatch_fails_and_reports_no_rollback_available(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        archive = make_tarball(tmp_path, {"app.py": "print('bad')"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        job = {
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": "0" * 64,
        }

        assert handler.handle_job(job) is False
        status, detail = status_log.calls[-1]
        assert status == "FAILED"
        assert "rollback" in detail
        assert not CURRENT_LINK.exists()

    def test_health_check_failure_rolls_back_to_previous_version(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        # Pre-install and activate a known-good previous version.
        old_dir = PACKAGES_DIR / "1.1.0"
        old_dir.mkdir(parents=True)
        (old_dir / "app.py").write_text("print('good old build')")
        setup_handler = OTAHandler()
        setup_handler._activate("1.1.0")
        setup_handler._save_state("1.1.0")

        # New version installs fine but fails its health check.
        archive = make_tarball(tmp_path, {"app.py": "print('broken new build')"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log, health_check_cmd=["false"])

        job = {
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": sha256_of(archive),
        }

        assert handler.handle_job(job) is False

        status, detail = status_log.calls[-1]
        assert status == "FAILED"
        assert detail.get("rolled_back_to") == "1.1.0"
        assert CURRENT_LINK.resolve() == old_dir.resolve()
        assert (CURRENT_LINK / "app.py").read_text() == "print('good old build')"

    def test_explicit_rollback_version_is_preferred_over_previous(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        # "Current" is 1.1.0, but the job explicitly names 1.0.0 as the
        # rollback target — that should win over the previously-running version.
        (PACKAGES_DIR / "1.1.0").mkdir(parents=True)
        (PACKAGES_DIR / "1.0.0").mkdir(parents=True)
        setup_handler = OTAHandler()
        setup_handler._activate("1.1.0")
        setup_handler._save_state("1.1.0")

        archive = make_tarball(tmp_path, {"app.py": "print('broken')"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log, health_check_cmd=["false"])

        job = {
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": sha256_of(archive),
            "rollbackVersion": "1.0.0",
        }

        assert handler.handle_job(job) is False
        _, detail = status_log.calls[-1]
        assert detail.get("rolled_back_to") == "1.0.0"
        assert CURRENT_LINK.resolve() == (PACKAGES_DIR / "1.0.0").resolve()

    def test_in_progress_steps_are_reported_in_order(
        self, isolated_cwd, tmp_path, fake_download, status_log
    ):
        archive = make_tarball(tmp_path, {"app.py": "print(1)"})
        fake_download.set_source(archive)
        handler = OTAHandler(on_status=status_log)

        handler.handle_job({
            "version": "1.2.0",
            "packageUrl": "https://example.com/pkg.tar.gz",
            "checksum": sha256_of(archive),
        })

        steps = [
            detail.get("step")
            for status, detail in status_log.calls
            if status == "IN_PROGRESS"
        ]
        assert steps == ["download", "verify", "extract", "activate", "health_check"]
