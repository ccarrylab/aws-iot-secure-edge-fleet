#!/usr/bin/env python3
"""
OTA Handler for Secure Edge Fleet
- Downloads package from URL
- Verifies SHA-256
- Installs to versioned directory
- Health check + automatic rollback
"""

import hashlib
import json
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Optional, Callable

PACKAGES_DIR = Path("packages")
CURRENT_LINK = PACKAGES_DIR / "current"
STATE_FILE = PACKAGES_DIR / "state.json"


class OTAHandler:
    def __init__(
        self,
        on_status: Optional[Callable[[str, dict], None]] = None,
        health_check_cmd: Optional[list] = None,
        health_check_timeout: int = 30,
    ):
        self.on_status = on_status or (lambda s, d: None)
        self.health_check_cmd = health_check_cmd
        self.health_check_timeout = health_check_timeout
        PACKAGES_DIR.mkdir(exist_ok=True)

    def handle_job(self, job_document: dict) -> bool:
        version = job_document.get("version")
        package_url = job_document.get("packageUrl")
        checksum = (job_document.get("checksum") or "").lower()
        rollback_version = job_document.get("rollbackVersion")

        if not version or not package_url:
            self._fail("Invalid job document: missing version or packageUrl")
            return False

        print(f"[OTA] Starting update to version {version}")
        self.on_status("IN_PROGRESS", {"version": version, "step": "download"})

        previous = self._get_current_version()
        tarball = None

        try:
            tarball = self._download(package_url, version)
            self.on_status("IN_PROGRESS", {"version": version, "step": "verify"})

            if checksum and not self._verify_checksum(tarball, checksum):
                raise RuntimeError("Checksum mismatch")

            self.on_status("IN_PROGRESS", {"version": version, "step": "extract"})
            self._extract(tarball, version)

            self.on_status("IN_PROGRESS", {"version": version, "step": "activate"})
            self._activate(version)

            self.on_status("IN_PROGRESS", {"version": version, "step": "health_check"})
            if not self._health_check():
                raise RuntimeError("Health check failed")

            self._save_state(version)
            self.on_status("SUCCEEDED", {"version": version, "previous": previous or ""})
            print(f"[OTA] Successfully updated to {version}")
            return True

        except Exception as e:
            print(f"[OTA] Update failed: {e}")
            target = rollback_version or previous
            if target and self._rollback(target):
                print(f"[OTA] Rolled back to {target}")
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
            if tarball and tarball.exists():
                tarball.unlink(missing_ok=True)

    def _download(self, url: str, version: str) -> Path:
        dest = PACKAGES_DIR / f"{version}.tar.gz"
        print(f"[OTA] Downloading {url} → {dest}")
        urllib.request.urlretrieve(url, dest)
        return dest

    def _verify_checksum(self, path: Path, expected: str) -> bool:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        actual = h.hexdigest()
        print(f"[OTA] Checksum actual={actual} expected={expected}")
        return actual == expected

    def _extract(self, tarball: Path, version: str) -> Path:
        install_dir = PACKAGES_DIR / version
        if install_dir.exists():
            shutil.rmtree(install_dir)
        install_dir.mkdir(parents=True)

        with tarfile.open(tarball, "r:gz") as tar:
            for member in tar.getmembers():
                member_path = (install_dir / member.name).resolve()
                if not str(member_path).startswith(str(install_dir.resolve())):
                    raise RuntimeError(f"Unsafe path in archive: {member.name}")
            tar.extractall(install_dir)

        print(f"[OTA] Extracted to {install_dir}")
        return install_dir

    def _activate(self, version: str):
        target = (PACKAGES_DIR / version).resolve()
        if CURRENT_LINK.exists() or CURRENT_LINK.is_symlink():
            CURRENT_LINK.unlink()
        CURRENT_LINK.symlink_to(target)
        print(f"[OTA] Activated {version}")

    def _health_check(self) -> bool:
        if not self.health_check_cmd:
            if not CURRENT_LINK.exists():
                return False
            ok = any(CURRENT_LINK.iterdir())
            print(f"[OTA] Default health check: {'OK' if ok else 'FAIL'}")
            return ok

        print(f"[OTA] Running health check: {self.health_check_cmd}")
        try:
            result = subprocess.run(
                self.health_check_cmd,
                timeout=self.health_check_timeout,
                capture_output=True,
                text=True,
            )
            print(f"[OTA] Health check exit={result.returncode}")
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("[OTA] Health check timed out")
            return False
        except Exception as e:
            print(f"[OTA] Health check error: {e}")
            return False

    def _rollback(self, version: str) -> bool:
        target = PACKAGES_DIR / version
        if not target.exists():
            print(f"[OTA] Rollback target {version} not found")
            return False
        try:
            self._activate(version)
            self._save_state(version)
            return True
        except Exception as e:
            print(f"[OTA] Rollback failed: {e}")
            return False

    def _get_current_version(self) -> Optional[str]:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text()).get("version")
            except Exception:
                pass
        if CURRENT_LINK.exists() and CURRENT_LINK.is_symlink():
            return CURRENT_LINK.resolve().name
        return None

    def _save_state(self, version: str):
        STATE_FILE.write_text(json.dumps({
            "version": version,
            "updated_at": int(time.time()),
        }, indent=2))

    def _fail(self, msg: str):
        print(f"[OTA] {msg}")
        self.on_status("FAILED", {"error": msg})