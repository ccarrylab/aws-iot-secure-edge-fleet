#!/usr/bin/env python3
"""
publish_release.py - build, hash, upload and deploy an edge-agent release.

Replaces the manual sequence behind this fleet's worst failure class: a human
pasting a sha256 that no longer matched the uploaded artifact. The checksum here
is computed from the exact bytes that get uploaded, and the artifact is
re-downloaded and re-hashed before the job is created - so a mismatch stops the
release instead of bricking the fleet.

    ./publish_release.py --version 1.4.0 --build-dir ./dist/edge-agent
    ./publish_release.py --version 1.4.0 --build-dir ./dist/edge-agent --dry-run
    ./publish_release.py --version 1.4.1 --build-dir ./dist/edge-agent --canary --thing-arn arn:...

  1. package  - deterministic .tar.gz: sorted entries, normalised metadata,
                pinned gzip mtime, symlinks refused. Same input => same sha256.
  2. hash     - sha256 of the tarball, written into the job document.
  3. upload   - S3, SSE-KMS if a key is configured.
  4. document - job document JSON (version, packageUrl, checksum, rollbackVersion).
  5. verify   - re-download the uploaded object and re-hash it. Refuse to
                publish on mismatch.
  6. create   - aws iot create-job with rollout config AND abort config, so a
                bad release stops itself instead of marching through the fleet.

Contract with the device agent (ota_handler.py) - do not diverge:
    VERSION_RE        ^[0-9A-Za-z][0-9A-Za-z._-]{0,62}$
    document fields   version, packageUrl, rollbackVersion, checksum
    checksum          sha256 of the .tar.gz, compared lowercase
    max package       268435456 bytes (256 MiB)
    URL scheme        https only
The agent downloads with a plain urlopen() and no AWS credentials, so the URL in
the job document MUST be publicly fetchable or presigned.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - argv lists only, never a shell
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone

# --- must match ota_handler.py ---------------------------------------------
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,62}$")
MAX_PACKAGE_BYTES = 256 * 1024 * 1024

# Reproducibility: a fixed mtime on every tar entry AND on the gzip header, so
# the same source tree always produces the same sha256. Without this, repacking a
# tested tree yields a different hash and you can no longer prove the artifact
# you shipped is the one you tested.
FIXED_MTIME = 0

# SigV4 presigned URLs cap out at 7 days. A device that is offline longer than
# the TTL receives a job it can never download.
PRESIGN_MAX_SECONDS = 604800

JUNK_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".idea", ".vscode",
}
JUNK_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
JUNK_SUFFIXES = (".pyc", ".pyo", ".log", ".swp", ".tmp", ".orig", ".rej")


def die(msg, code=1):
    sys.stderr.write("\nERROR: %s\n" % msg)
    sys.exit(code)


def info(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def run(cmd, dry_run=False):
    """Shell out to the AWS CLI. Prints the command so the run is auditable."""
    info("  $ " + " ".join(cmd))
    if dry_run:
        return ""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,  # nosec B603 - argv list built by this script, no shell
                          universal_newlines=True)
    if proc.returncode != 0:
        die("command failed (%d): %s\n%s"
            % (proc.returncode, " ".join(cmd), (proc.stderr or "").strip()))
    return (proc.stdout or "").strip()


# ---------------------------------------------------------------------------
# 1. package
# ---------------------------------------------------------------------------

def collect_files(build_dir):
    """Sorted relative paths, junk excluded, symlinks refused.

    The agent's extractor rejects symlink members, so a build containing one
    would fail on EVERY device. Catching it at publish time turns a fleet-wide
    outage into a one-line local error.
    """
    if not os.path.isdir(build_dir):
        die("build dir not found: %s" % build_dir)

    out = []
    for root, dirs, files in os.walk(build_dir):
        dirs[:] = sorted(d for d in dirs if d not in JUNK_DIRS)
        for name in sorted(files):
            if name in JUNK_FILES or name.endswith(JUNK_SUFFIXES):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, build_dir)
            if os.path.islink(full):
                die("refusing to package a symlink: %s\n"
                    "  The device agent rejects symlink archive members, so this\n"
                    "  build would fail on every device. Replace it with a real\n"
                    "  file (copy the target in) and re-run." % rel)
            if not os.path.isfile(full):
                die("refusing to package a special file: %s" % rel)
            out.append(rel)

    if not out:
        die("build dir contains no packageable files: %s" % build_dir)
    return sorted(out)


def pack(build_dir, out_path):
    """Write a deterministic .tar.gz to out_path. Returns the file list."""
    rels = collect_files(build_dir)
    tar_path = out_path + ".tmp.tar"
    try:
        with tarfile.open(tar_path, "w") as tar:
            for rel in rels:
                full = os.path.join(build_dir, rel)
                info_ = tar.gettarinfo(full, arcname=rel)
                info_.uid = 0
                info_.gid = 0
                info_.uname = ""
                info_.gname = ""
                info_.mtime = FIXED_MTIME
                info_.mode = 0o755 if (info_.mode & 0o100) else 0o644
                with open(full, "rb") as fh:
                    tar.addfile(info_, fh)

        with open(tar_path, "rb") as src, open(out_path, "wb") as dst:
            with gzip.GzipFile(filename="", mode="wb", fileobj=dst,
                               mtime=FIXED_MTIME, compresslevel=9) as gz:
                shutil.copyfileobj(src, gz, 65536)
    finally:
        if os.path.exists(tar_path):
            os.remove(tar_path)
    return rels


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 2-4. document
# ---------------------------------------------------------------------------

def build_document(version, package_url, checksum, rollback_version=None, s3_uri=None):
    """Exactly the fields ota_handler.handle_job() reads, and nothing it guesses."""
    doc = {
        "version": version,
        "packageUrl": package_url,
        "checksum": checksum,
        "publishedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if rollback_version:
        doc["rollbackVersion"] = rollback_version
    # Emitted always in practice (computed from bucket + version in main).
    # A presigned URL dies after 7 days, so a device offline longer receives a
    # job it can never download; the s3:// path has no such cliff. Older agents
    # ignore the field and read packageUrl, so BOTH are always emitted.
    if s3_uri:
        doc["packageS3Uri"] = s3_uri
    return doc


def abort_config(fail_pct, min_things=1):
    """The AWS-native safety net. Without this a bad release marches through the
    whole fleet and nothing stops it."""
    return {
        "criteriaList": [
            {"action": "CANCEL", "failureType": "FAILED",
             "minNumberOfExecutedThings": min_things,
             "thresholdPercentage": fail_pct},
            {"action": "CANCEL", "failureType": "TIMED_OUT",
             "minNumberOfExecutedThings": max(min_things, 3),
             "thresholdPercentage": max(fail_pct, 50)},
        ]
    }


# ---------------------------------------------------------------------------
# 6. create
# ---------------------------------------------------------------------------
def resolve_thing_group_arn(name, dry_run=False):
    if dry_run:
        return "arn:aws:iot:REGION:ACCOUNT:thinggroup/%s" % name
    return run(["aws", "iot", "describe-thing-group",
                "--thing-group-name", name,
                "--query", "thingGroupArn", "--output", "text"])


def latest_deployed_version(exclude_job_id, dry_run=False):
    """Best-effort: the version from the most recent COMPLETED job."""
    if dry_run:
        return None
    try:
        raw = run(["aws", "iot", "list-jobs", "--status", "COMPLETED",
                   "--max-results", "50", "--output", "json"])
        jobs = json.loads(raw or "[]")["jobs"]
    except Exception:
        return None
    jobs = [j for j in jobs if j.get("jobId") != exclude_job_id]
    if not jobs:
        return None
    jobs.sort(key=lambda j: j.get("createdAt", ""), reverse=True)
    try:
        doc = json.loads(run(["aws", "iot", "describe-job",
                              "--job-id", jobs[0]["jobId"],
                              "--query", "document", "--output", "text"]))
        return doc.get("version")
    except Exception:
        return None


def presign(bucket, key, ttl, dry_run=False):
    if dry_run:
        return "https://%s.s3.amazonaws.com/%s?X-Amz-Signature=DRYRUN" % (bucket, key)
    return run(["aws", "s3", "presign", "s3://%s/%s" % (bucket, key),
                "--expires-in", str(ttl)])


def verify_uploaded(url, expected_sha):
    """Re-download what we just uploaded and hash it. This is the check that
    would have caught the hand-pasted checksums."""
    info("  fetching the uploaded object to re-hash it ...")
    h = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(url, timeout=60) as resp:  # nosec B310 - presigned https URL generated earlier in this script
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PACKAGE_BYTES:
                die("uploaded object exceeds the agent's 256 MiB download cap")
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected_sha:
        die("UPLOADED ARTIFACT DOES NOT MATCH\n"
            "  local  sha256: %s\n"
            "  remote sha256: %s\n"
            "  Nothing was published." % (expected_sha, actual))
    info("  verified: remote sha256 matches the local artifact")
    return True


# ---------------------------------------------------------------------------
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Build, hash, upload and deploy an edge-agent release.")
    p.add_argument("--version", required=True, help="release version, e.g. 1.4.0")
    p.add_argument("--build-dir", required=True,
                   help="directory whose CONTENTS become the package root")
    p.add_argument("--bucket", default=os.environ.get("OTA_BUCKET", ""),
                   help="S3 bucket (or set OTA_BUCKET)")
    p.add_argument("--key-prefix", default="packages/",
                   help="S3 key prefix (default: packages/)")
    p.add_argument("--thing-group", default="", help="IoT thing group to target")
    p.add_argument("--thing-arn", default="",
                   help="target a single thing ARN instead of the group (canary)")
    p.add_argument("--kms-key", default=os.environ.get("OTA_KMS_KEY", ""),
                   help="KMS key id for SSE-KMS")
    p.add_argument("--rollback-version", default="",
                   help="version devices fall back to; auto-detected if omitted")
    p.add_argument("--url-ttl-hours", type=int, default=168,
                   help="presigned URL lifetime in hours (max 168)")
    p.add_argument("--rollout-per-minute", type=int, default=10,
                   help="how many devices start the job per minute")
    p.add_argument("--abort-failure-pct", type=int, default=20,
                   help="cancel the job once this percent of devices have failed")
    p.add_argument("--canary", action="store_true",
                   help="target one device, abort on the first failure")
    p.add_argument("--dry-run", action="store_true",
                   help="show every command, change nothing")
    p.add_argument("--verify-only", metavar="TARBALL",
                   help="re-hash an existing tarball and exit")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if args.verify_only:
        info("sha256  %s  %s" % (sha256_file(args.verify_only), args.verify_only))
        return 0

    if not VERSION_RE.match(args.version):
        die("invalid version %r\n  must match %s (the agent rejects anything else)"
            % (args.version, VERSION_RE.pattern))

    if not args.bucket:
        die("no bucket: pass --bucket or set OTA_BUCKET")

    if args.canary:
        if not args.thing_arn:
            die("--canary needs --thing-arn so it targets exactly one device")
        args.abort_failure_pct = 1
        info("canary mode: one target, abort on the first failure")

    ttl = min(args.url_ttl_hours * 3600, PRESIGN_MAX_SECONDS)
    if args.url_ttl_hours * 3600 > PRESIGN_MAX_SECONDS:
        info("note: presigned URLs cap at 7 days; using %d seconds" % PRESIGN_MAX_SECONDS)

    info("=== publishing edge-agent %s ===" % args.version)
    if args.dry_run:
        info("(dry run - nothing will be created)")

    info("")
    info("[1/6] packaging %s" % args.build_dir)
    tmpdir = tempfile.mkdtemp(prefix="ota-publish-")
    tarball = os.path.join(tmpdir, "%s.tar.gz" % args.version)
    rels = pack(args.build_dir, tarball)
    size = os.path.getsize(tarball)
    info("  %d files, %d bytes" % (len(rels), size))
    if size > MAX_PACKAGE_BYTES:
        die("package is %d bytes; the agent refuses anything over %d (256 MiB)"
            % (size, MAX_PACKAGE_BYTES))
    info("  contents: %s%s" % (", ".join(rels[:6]), " ..." if len(rels) > 6 else ""))

    info("")
    info("[2/6] hashing")
    checksum = sha256_file(tarball)
    info("  sha256 %s" % checksum)

    key = "%s%s.tar.gz" % (args.key_prefix, args.version)
    s3_uri = "s3://%s/%s" % (args.bucket, key)

    info("")
    info("[3/6] uploading to %s" % s3_uri)
    put = ["aws", "s3", "cp", tarball, s3_uri,
           "--content-type", "application/gzip", "--no-progress"]
    if args.kms_key:
        put += ["--sse", "aws:kms", "--sse-kms-key-id", args.kms_key]
    else:
        info("  WARNING: no --kms-key given; uploading without SSE-KMS")
    run(put, args.dry_run)

    info("")
    info("[4/6] building the job document")
    job_id = "edge-agent-%s-%s" % (
        args.version, datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    url = presign(args.bucket, key, ttl, args.dry_run)

    rollback = args.rollback_version or latest_deployed_version(job_id, args.dry_run)
    if rollback:
        info("  rollbackVersion: %s" % rollback)
    else:
        info("  rollbackVersion: none - no completed job to fall back to")

    document = build_document(args.version, url, checksum, rollback, s3_uri=s3_uri)
    info(json.dumps(document, indent=2))

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(document, fh)
        document_path = fh.name

    info("")
    info("[5/6] verifying the uploaded artifact")
    if args.dry_run:
        info("  (skipped in dry run)")
    else:
        verify_uploaded(url, checksum)

    info("")
    info("[6/6] creating the job")
    target = (["--targets", args.thing_arn] if args.thing_arn
              else ["--targets", resolve_thing_group_arn(args.thing_group or "%s-fleet" % "secure-edge-fleet", args.dry_run)])

    create = ["aws", "iot", "create-job",
              "--job-id", job_id,
              "--document", "file://%s" % document_path,
              "--description", "edge-agent %s" % args.version,
              "--target-selection", "SNAPSHOT"] + target + [
        "--rollout-config", json.dumps({"maximumPerMinute": args.rollout_per_minute}),
        "--abort-config", json.dumps(abort_config(args.abort_failure_pct)),
    ]
    run(create, args.dry_run)

    os.unlink(document_path)
    info("")
    info("published %s (job %s)" % (args.version, job_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
