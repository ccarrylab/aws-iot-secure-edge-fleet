# Fixes — what changed, and how to apply it

Companion to `aws-iot-edge-fleet-review-report.pdf`. Every file here is meant to
be dropped into the repo as-is.

**Verified:** the hardened `ota_handler.py` was exercised against **31 checks**
covering both your existing test expectations and the new security behaviour —
**31/31 pass**, including the symlink case you currently carry as
`xfail(strict=True)`, which now passes for real.

---

## Files

| File | Goes to | What it does |
|---|---|---|
| `ota_handler.py` | `device-agent/ota_handler.py` | Drop-in replacement. Fixes C1, C2, C3, H1, H4 (download), C5 (default check), plus a reinstall guard found while testing. |
| `conftest.py` | `device-agent/tests/conftest.py` | Updated `fake_download` — the hardened `_download` streams via `urlopen`, so the fixture patches that as well as `urlretrieve`. |
| `test_hardening.py` | `device-agent/tests/test_hardening.py` | New. 24 tests: version traversal, the prefix-bypass sibling, link members, missing/malformed checksum, non-HTTPS, size cap, atomic activation, state durability, health check, reinstall guard. |
| `hardening.tf` | merge into `infrastructure/main.tf` | Replaces the device policy (C4), the provisioning role (H5), and the OTA bucket (H8). Adds variable validations. |
| `ota-boot-guard.sh` | `/usr/local/bin/ota-boot-guard.sh` | The local rollback guard that survives a release which cannot start (C5). |
| `edge-agent.service` | `/etc/systemd/system/` | Runs the agent as an unprivileged user with the guard wired as `ExecStartPre`. |
| `agent-patches.md` | — | Precise before/after patches for `agent.py` (H2, H3, H6, H7b). |
| `aws-iot-edge-fleet-review-report.pdf` | — | The full review: all findings, evidence, severity, and the roadmap. |

---

## ⚠️ Two test changes are REQUIRED, or your suite will fail

These are not optional edits — they are the tests encoding the old behaviour.

### 1. Delete the `xfail` marker — it now passes

`test_rejects_symlink_member_escaping_install_dir` is marked:

```python
@pytest.mark.xfail(
    reason="... Fix _extract to also validate SYMTYPE/LNKTYPE member.linkname, "
           "then remove this xfail.",
    strict=True,
)
```

`_extract` now validates link members, so this test **passes** — and because the
marker is `strict=True`, an XPASS is reported as a **failure**. Remove the
decorator (and the now-stale comment). The fix is exactly the one the docstring
asks for; the assertion itself needs no change, because the rejection message
still contains `"Unsafe path"`.

### 2. Invert the checksum test

`test_missing_checksum_skips_verification_entirely` asserts the old behaviour:

> Documents current behavior: `handle_job` only verifies the checksum
> `if checksum and not self._verify_checksum(...)`. A job document with no
> checksum field skips verification…

That is the bug. A missing checksum is now a **rejected job**. Replace that test
with `TestChecksumRequired::test_missing_checksum_fails_the_update` from
`test_hardening.py`, or simply delete it — the new file covers it.

### Also worth knowing

- **Any test that expects a non-HTTPS `packageUrl` to install** will now fail —
  non-HTTPS is refused by design.
- **Reinstalling the currently-active version is refused** unless the handler is
  constructed with `allow_reinstall=True`. This is new behaviour (see below) and
  no test covered it.
- `_extract` now unpacks into `packages/.staging-<version>` and swaps into place
  on success, so the final directory is created by `os.replace` rather than
  `mkdir`. Tests that inspect the result after `_extract` returns are unaffected.

---

## Finding → change

| # | Finding | Fixed in | Change |
|---|---|---|---|
| C1 | `version` from the job document used raw as a filesystem path, then `rmtree`'d | `ota_handler.py` | `_safe_version()` validates against `^[0-9A-Za-z][0-9A-Za-z._-]{0,62}$`, rejects `..`, and is applied in `handle_job`, `_download`, `_extract`, `_rollback` and `_activate`. |
| C2 | Tar guard used `str.startswith` (prefix bypass); link members never rejected | `ota_handler.py` | `Path.is_relative_to()` for real containment; `issym()`/`islnk()`/`isdev()` members refused; member-count and extracted-size caps; `filter="data"` where available. |
| C3 | Checksum verification silently skipped when the field was absent | `ota_handler.py` | Checksum is required and must match `[0-9a-f]{64}`; anything malformed fails the job instead of proceeding. |
| C4 | Device policy gave every device access to every other device | `hardening.tf` | All resources scoped with `${iot:Connection.Thing.ThingName}`; the `Resource = "*"` job statement scoped to the device's own thing. |
| C5 | Rollback could not fire on a bad boot; default health check always passed | `ota-boot-guard.sh`, `edge-agent.service`, `ota_handler.py` | Shell-level boot guard with a boot counter runs before the app; systemd `WatchdogSec`; default health check now fails on a missing/empty/dangling release. |
| H1 | `unlink()` then `symlink_to()` left a window with no `current`; state file written non-atomically | `ota_handler.py` | `os.symlink` to a temp name + `os.replace` + directory `fsync`; state written temp+fsync+`replace`. |
| H2 | Telemetry publish killed the process; no will; no re-subscribe on resume | `agent-patches.md` | Bounded retry with backoff, Last Will and Testament for an `offline` status, re-subscribe on resume. |
| H3 | Job status could be reported against the wrong job; no OTA concurrency guard | `agent-patches.md`, `ota_handler.py` | Job id bound per execution + in-flight set + a lock; `handle_job()` accepts an optional `job_id`. |
| H4 | Integrity without authenticity; unhardened download | `ota_handler.py`, `hardening.tf` | HTTPS enforced, 30s timeout, 256 MB cap, streamed to `.part` then atomic rename, retry with backoff, disk-space precheck. Signing itself is a design decision — see below. |
| H5 | Provisioning role over-permissioned, `Resource = "*"` | `hardening.tf` | Removed `iot:CreatePolicy`, `AttachPrincipalPolicy`, `GetPolicy`, `ListPolicyPrincipals`, `ListPrincipalPolicies`, `CreateCertificateFromCsr`; every remaining action scoped to its real resource. |
| H6 | SUBACK race; callbacks swallowed their own errors; missing jobs `/rejected` | `agent-patches.md` | `future.result()` on every subscribe; try/except-into-`self.error` in every callback; subscribe to the Jobs rejection topic. |
| H7 | Serial regenerated per run and too narrow; first-boot crash; 0600 window | `agent-patches.md` | Serial persisted with `O_EXCL`, hardware-derived where possible, 64 bits; `CERTS_DIR.mkdir` before use; CA vendored not downloaded; secrets created at 0600 via `os.open`. |
| H8 | OTA bucket missing encryption, TLS enforcement, lifecycle, ownership controls | `hardening.tf` | SSE-KMS, `DenyNonTLS` bucket policy, `BucketOwnerEnforced`, noncurrent expiry, `force_destroy` gated on environment, plus a least-privilege publisher role. |
| — | **New:** reinstalling the active version destroyed the only copy a rollback could use | `ota_handler.py` | Extraction is staged; a corrupt archive can no longer take out the running release. Reinstalling the active version is refused unless `allow_reinstall=True`. |
| — | **New:** a corrupt `state.json` silently removed the rollback target | `ota_handler.py` | `_get_current_version()` reports the unreadable state file instead of swallowing it. |

---

## What I deliberately did **not** change

**`agent.py` is patched, not replaced.** I can't exercise `awsiot` against a real
broker from here, and a blind rewrite of working provisioning code is a worse
trade than four small, reviewable patches. `agent-patches.md` gives exact
before/after blocks for each.

**Package signing (H4) needs a decision from you, not a patch.** Integrity is
not authenticity: the checksum travels in the same job document as the URL, so
if the publish path is compromised the attacker just recomputes it. Closing that
requires choosing a signing key strategy and where the public key lives on the
device — AWS Signer with an asymmetric KMS key, or cosign/sigstore, with the
public key pinned at manufacture rather than fetched at runtime. That's a design
call with real operational consequences, so the review recommends it rather than
guessing.

**Staged rollout and abort config** are not in `hardening.tf` because the job
creation lives outside Terraform today (it's a hand-run `aws iot create-job`).
The highest-value follow-up is to codify release publishing — build → sign →
hash → upload → create job with `rollout_config` and `abort_config` — so the
checksum can never disagree with the artifact it describes.

**AWS's managed Software Package Catalog** (`aws_iot_software_package` /
`aws_iot_software_package_version`) is worth a spike before further investment
in the hand-rolled S3 + sha256 + job-document path. It handles versioning,
naming and job creation natively and integrates with code signing.

---

## Suggested order

1. Drop in `ota_handler.py`, `conftest.py`, `test_hardening.py`; make the two
   test edits; run `pytest`.
2. Apply `hardening.tf` to a **dev** environment. Verify a canary device can
   still connect, publish telemetry and receive a Job — the policy change is
   live for existing devices as soon as the new version lands.
3. Apply the `agent.py` patches, starting with H7 (the first-boot crash is a
   real one).
4. Install `ota-boot-guard.sh` + `edge-agent.service`, and make the agent call
   `sd_notify(READY=1)` once it is genuinely up — otherwise the watchdog will
   restart a healthy process.
