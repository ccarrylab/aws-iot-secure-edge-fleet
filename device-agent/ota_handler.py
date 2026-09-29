#!/usr/bin/env python3
"""
OTA Handler for Secure Edge Fleet
- Downloads package from URL (https only, size-capped, atomic install)
- Verifies SHA-256 (REQUIRED - fails closed)
- Installs to a versioned directory (validated version, link-safe extraction)
- Activates atomically via a symlink swap
- Health check + automatic rollback
"""

import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - argv list, never a shell; command is device config, not job input
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

PACKAGES_DIR = Path("packages")
CURRENT_LINK = PACKAGES_DIR / "current"
STATE_FILE = PACKAGES_DIR / "state.json"

# --------------------------------------------------------------------------
# Hardening limits. All of these are deliberately conservative: this code
# consumes untrusted input (a job document and the archive it points at).
# --------------------------------------------------------------------------
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,62}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
DOWNLOAD_TIMEOUT_S = 30
DOWNLOAD_ATTEMPTS = 3


class OTAHandler:
    def __init__(
        self,
        on_status: Optional[Callable[[str, dict], None]] = None,
        health_check_cmd: Optional[list] = None,
        health_check_timeout: int = 30,
        allow_reinstall: bool = False,
        fetcher=None,
    ):
        self.on_status = on_status or (lambda s, d: None)
        self.health_check_cmd = health_check_cmd
        self.health_check_timeout = health_check_timeout
        self.allow_reinstall = allow_reinstall
        # Optional callable (uri, dest) -> None that reads an s3:// object using
        # temporary credentials from the IoT credential provider. When absent,
        # the handler requires a presigned https packageUrl exactly as before.
        self.fetcher = fetcher
        PACKAGES_DIR.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_version(version: object) -> str:
        """A version identifier is a LABEL, never a path component.

        This is the fix for the arbitrary-path-deletion primitive: without it
        a job document of {"version": "../../anything"} reaches
        PACKAGES_DIR / version and then shutil.rmtree().
        """
        if not isinstance(version, str) or not VERSION_RE.match(version):
            raise ValueError("Rejected unsafe version identifier: %r" % (version,))
        if ".." in version:
            raise ValueError("Rejected version containing '..': %r" % (version,))
        return version

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _write_json_atomic(path: Path, payload: dict) -> None:
        """Write via a temp file + fsync + os.replace so a power cut cannot
        leave a truncated file behind."""
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ------------------------------------------------------------------
    # Job handling
    # ------------------------------------------------------------------
    def handle_job(self, job_document: dict, job_id: Optional[str] = None) -> bool:
        if not isinstance(job_document, dict):
            self._fail("Invalid job document: not an object")
            return False

        # 1. version is validated BEFORE it is used to build any path.
        try:
            version = self._safe_version(job_document.get("version"))
        except ValueError as e:
            self._fail(str(e))
            return False

        package_url = job_document.get("packageUrl")
        package_s3_uri = job_document.get("packageS3Uri")
        rollback_version = job_document.get("rollbackVersion")

        # Prefer the s3:// path when the device can mint its own credentials:
        # a presigned URL expires (SigV4 caps at 7 days), so a device that is
        # offline longer than that receives a job it can never download.
        use_s3 = bool(package_s3_uri) and self.fetcher is not None

        if use_s3:
            if not isinstance(package_s3_uri, str) or not package_s3_uri.startswith("s3://"):
                self._fail("packageS3Uri must be an s3:// URI")
                return False
        elif not package_url or not isinstance(package_url, str):
            self._fail("Invalid job document: missing packageUrl")
            return False

        # 2. checksum is REQUIRED and must be well formed - no silent skip.
        checksum = (job_document.get("checksum") or "").strip().lower()
        if not SHA256_RE.match(checksum):
            self._fail("Job document must include a valid sha256 checksum")
            return False

        # 3. never fetch a package over plaintext. The s3 lane is SigV4 over
        #    TLS and carries no URL, so it is exempt from this specific check.
        if not use_s3 and not package_url.lower().startswith("https://"):
            self._fail("Refusing non-HTTPS package URL: %s" % package_url)
            return False

        if rollback_version is not None:
            try:
                rollback_version = self._safe_version(rollback_version)
            except ValueError as e:
                self._fail("Invalid rollbackVersion: %s" % e)
                return False

        print("[OTA] Starting update to version %s" % version)
        self.on_status("IN_PROGRESS", {"version": version, "step": "download"})

        previous = self._get_current_version()

        # Re-installing the version that is already active overwrites the only
        # copy of the running build, which leaves a rollback with nothing to
        # fall back to. Refuse it unless the operator explicitly opts in.
        if previous == version and not self.allow_reinstall:
            self._fail(
                "Version %s is already installed; refusing to overwrite the "
                "running release (pass allow_reinstall=True to force)" % version
            )
            return False

        tarball = None

        try:
            self._check_disk_space()
            if use_s3:
                tarball = self._download_s3(package_s3_uri, version)
            else:
                tarball = self._download(package_url, version)
            self.on_status("IN_PROGRESS", {"version": version, "step": "verify"})

            if not self._verify_checksum(tarball, checksum):
                raise RuntimeError("Checksum mismatch")

            self.on_status("IN_PROGRESS", {"version": version, "step": "extract"})
            self._extract(tarball, version)

            self.on_status("IN_PROGRESS", {"version": version, "step": "activate"})
            self._activate(version)

            self.on_status("IN_PROGRESS", {"version": version, "step": "health_check"})
            if not self._health_check():
                raise RuntimeError("Health check failed")

            self._save_state(version, checksum=checksum)
            self.on_status("SUCCEEDED", {"version": version, "previous": previous or ""})
            print("[OTA] Successfully updated to %s" % version)
            return True

        except Exception as e:
            print("[OTA] Update failed: %s" % e)
            target = rollback_version or previous
            if target and self._rollback(target):
                print("[OTA] Rolled back to %s" % target)
                self.on_status("FAILED", {
                    "version": version,
                    "error": str(e),
                    "rolled_back_to": target,
                })
            else:
                self.on_status("FAILED", {
                    "version": version,
                    "error": str(e),
                    "rollback": "failed or not available",
                })
            return False
        finally:
            if tarball is not None:
                tarball.unlink(missing_ok=True)
                tarball.with_name(tarball.name + ".part").unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------
    def _check_disk_space(self) -> None:
        try:
            free = shutil.disk_usage(PACKAGES_DIR).free
        except OSError:
            return
        if free < MAX_DOWNLOAD_BYTES:
            raise RuntimeError(
                "Insufficient free disk space for an update: %d bytes free" % free
            )

    def _download(self, url: str, version: str) -> Path:
        """https only, timeout, size cap, streamed to a .part file and then
        renamed atomically so a partial download can never masquerade as a
        complete package."""
        version = self._safe_version(version)
        dest = PACKAGES_DIR / ("%s.tar.gz" % version)
        part = dest.with_name(dest.name + ".part")

        last_error = None
        for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
            try:
                print("[OTA] Downloading %s -> %s (attempt %d)" % (url, dest, attempt))
                with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT_S) as resp:  # nosec B310 - handle_job() rejects non-https URLs first
                    declared = resp.headers.get("Content-Length")
                    if declared and declared.isdigit() and int(declared) > MAX_DOWNLOAD_BYTES:
                        raise RuntimeError("Package too large: %s bytes" % declared)

                    written = 0
                    with open(part, "wb") as f:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > MAX_DOWNLOAD_BYTES:
                                raise RuntimeError("Package exceeded size limit mid-download")
                            f.write(chunk)
                        f.flush()
                        os.fsync(f.fileno())

                os.replace(part, dest)
                return dest
            except Exception as e:
                last_error = e
                part.unlink(missing_ok=True)
                if attempt < DOWNLOAD_ATTEMPTS:
                    time.sleep(attempt)
        raise RuntimeError("Download failed after %d attempts: %s" % (DOWNLOAD_ATTEMPTS, last_error))

    def _download_s3(self, s3_uri: str, version: str) -> Path:
        """Read the object with temporary credentials, atomically.

        Same contract as _download: stream to a .part file, then rename, so a
        partial read can never masquerade as a complete package. The fetcher
        owns the credentials exchange; this method owns retries, the size cap
        and the atomic rename.
        """
        version = self._safe_version(version)
        dest = PACKAGES_DIR / ("%s.tar.gz" % version)
        part = dest.with_name(dest.name + ".part")

        last_error = None
        for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
            try:
                print("[OTA] Fetching %s -> %s (attempt %d)" % (s3_uri, dest, attempt))
                self.fetcher(s3_uri, part)
                size = part.stat().st_size
                if size > MAX_DOWNLOAD_BYTES:
                    raise RuntimeError("Package too large: %s bytes" % size)
                if size == 0:
                    raise RuntimeError("Package is empty")
                os.replace(part, dest)
                return dest
            except Exception as e:
                last_error = e
                part.unlink(missing_ok=True)
                if attempt < DOWNLOAD_ATTEMPTS:
                    time.sleep(attempt)
        raise RuntimeError("S3 fetch failed after %d attempts: %s" % (DOWNLOAD_ATTEMPTS, last_error))

    def _verify_checksum(self, path: Path, expected: str) -> bool:
        actual = self._sha256(path)
        print("[OTA] Checksum actual=%s expected=%s" % (actual, expected))
        return actual == expected

    # ------------------------------------------------------------------
    # Extract
    # ------------------------------------------------------------------
    def _extract(self, tarball: Path, version: str) -> Path:
        version = self._safe_version(version)
        install_dir = PACKAGES_DIR / version

        # Unpack into a staging directory first. Wiping install_dir up front
        # destroys a known-good copy before we know the replacement even
        # unpacks - so a corrupt archive could take out the running release,
        # which is precisely the copy a rollback needs to fall back to.
        staging = PACKAGES_DIR / (".staging-" + version)
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        root = staging.resolve()

        with tarfile.open(tarball, "r:gz") as tar:
            members = tar.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise RuntimeError("Unsafe path in archive: too many members")

            for m in members:
                # Links and device nodes are never materialised. A symlink
                # member pointing outside the install root would otherwise be
                # created here and then written THROUGH by a later member,
                # which bypasses any name-based check entirely.
                if m.issym() or m.islnk():
                    raise RuntimeError(
                        "Unsafe path in archive: link member %r -> %r" % (m.name, m.linkname)
                    )
                if m.isdev():
                    raise RuntimeError(
                        "Unsafe path in archive: device node %r" % (m.name,)
                    )

                target = (root / m.name).resolve()
                # is_relative_to() is a REAL containment test. The previous
                # str.startswith() was a prefix match, so a sibling directory
                # such as "1.0.0evil" passed a check meant to reject escapes.
                if not target.is_relative_to(root):
                    raise RuntimeError("Unsafe path in archive: %r" % (m.name,))

            if sum(m.size for m in members if m.isfile()) > MAX_EXTRACTED_BYTES:
                raise RuntimeError("Unsafe path in archive: extracted size limit exceeded")

            try:
                tar.extractall(root, filter="data")
            except TypeError:
                # filter= exists on 3.9.17+/3.10.12+/3.11.4+/3.12+; the explicit
                # checks above keep older patch levels safe.
                tar.extractall(root)  # nosec B202 - members validated above (no links/devices, contained paths, size caps); fallback for Pythons without filter=

        # Swap into place only after a completely clean unpack.
        if install_dir.is_symlink():
            install_dir.unlink()
        elif install_dir.exists():
            shutil.rmtree(install_dir)
        os.replace(staging, install_dir)

        print("[OTA] Extracted to %s" % install_dir)
        return install_dir

    # ------------------------------------------------------------------
    # Activate
    # ------------------------------------------------------------------
    def _activate(self, version: str) -> None:
        target = (PACKAGES_DIR / self._safe_version(version)).resolve()
        if not target.is_dir():
            raise RuntimeError("Activation target does not exist: %s" % target)

        # Create the new link under a temporary name, then swap it in with
        # os.replace (atomic rename). The old code unlinked first, leaving a
        # window in which no 'current' existed at all - a power cut there
        # bricks the device.
        tmp = CURRENT_LINK.with_name(CURRENT_LINK.name + ".tmp")
        tmp.unlink(missing_ok=True)
        os.symlink(target, tmp)
        os.replace(tmp, CURRENT_LINK)

        # Durability: make sure the directory entry itself is on disk.
        try:
            dir_fd = os.open(str(PACKAGES_DIR), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, AttributeError):
            pass

        print("[OTA] Activated %s" % version)

    # ------------------------------------------------------------------
    # Health check + rollback
    # ------------------------------------------------------------------
    def _health_check(self) -> bool:
        if not self.health_check_cmd:
            # Fail-closed default. The previous "is the directory non-empty?"
            # test could never fail for a real package, which meant the
            # automatic rollback never fired in the default configuration.
            # This version still accepts any real install, but it rejects a
            # dangling symlink, a missing target, and an empty payload.
            if not CURRENT_LINK.is_symlink() or not CURRENT_LINK.is_dir():
                print("[OTA] Default health check: FAIL (no valid current release)")
                return False
            has_payload = any(
                child.is_file() for child in CURRENT_LINK.rglob("*") if child.is_file()
            )
            print("[OTA] Default health check: %s" % ("OK" if has_payload else "FAIL"))
            return has_payload

        print("[OTA] Running health check: %s" % (self.health_check_cmd,))
        try:
            result = subprocess.run(  # nosec B603 - argv list, no shell; command comes from device env config
                self.health_check_cmd,
                timeout=self.health_check_timeout,
                capture_output=True,
                text=True,
            )
            print("[OTA] Health check exit=%s" % result.returncode)
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("[OTA] Health check timed out")
            return False
        except Exception as e:
            print("[OTA] Health check error: %s" % e)
            return False

    def _rollback(self, version: str) -> bool:
        try:
            version = self._safe_version(version)
        except ValueError as e:
            print("[OTA] Rollback refused: %s" % e)
            return False

        target = PACKAGES_DIR / version
        if not target.is_dir():
            print("[OTA] Rollback target %s not found" % version)
            return False
        if not any(c.is_file() for c in target.rglob("*") if c.is_file()):
            # An empty target is a WARNING, not a refusal. The primary
            # protection against an empty release is upstream: _extract()
            # stages the archive and only swaps it in after validating its
            # members, so a failed extraction cannot leave a version
            # directory empty. Refusing here as well broke the documented
            # contract that any existing version directory is a valid
            # rollback target.
            print(
                "[OTA] WARNING: rollback target %s is empty - "
                "the agent may not start" % version
            )
        try:
            self._activate(version)
            self._save_state(version)
            return True
        except Exception as e:
            print("[OTA] Rollback failed: %s" % e)
            return False

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def _get_current_version(self) -> Optional[str]:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text()).get("version")
            except Exception as e:
                # Do NOT swallow this. A corrupt state file used to return
                # None, which silently removed the rollback target.
                print("[OTA] WARNING: unreadable state file %s: %s" % (STATE_FILE, e))
        if CURRENT_LINK.is_symlink():
            return CURRENT_LINK.resolve().name
        return None

    def _save_state(self, version: str, checksum: Optional[str] = None) -> None:
        self._write_json_atomic(STATE_FILE, {
            "version": version,
            "checksum": checksum,
            "updated_at": int(time.time()),
        })

    def _fail(self, msg: str) -> None:
        print("[OTA] %s" % msg)
        self.on_status("FAILED", {"error": msg})
