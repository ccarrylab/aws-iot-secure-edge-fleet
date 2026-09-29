# AWS IoT Secure Edge Fleet

Zero-touch device provisioning and safe OTA updates for AWS IoT, built with Terraform and Python.

[![Terraform](https://img.shields.io/badge/Terraform-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Status:** reference implementation that has been through a security-hardening pass (see [Security notes](#security-notes)). Provisioning and OTA work end to end, but one structural gap remains before a production fleet: release integrity rests on a SHA-256 in the job document, not a signature. Read [Security notes](#security-notes) before deploying beyond a dev environment.

Devices provision themselves on first boot using a shared claim certificate, then get a unique permanent identity — no manual per-device setup. OTA updates are delivered through AWS IoT Jobs, verified against a checksum, and rolled back automatically if the health check fails after install.

## Features

- **Zero-touch provisioning** — devices exchange a one-time claim certificate for a unique X.509 certificate on first boot
- **Safe OTA** — HTTPS-only, size-capped download; required SHA-256 verification; link-safe staged extraction; atomic symlink activation; health check; automatic rollback on failure
- **Rollback that survives a build that won't start** — a local boot guard runs before the agent and reverts an activation that was never confirmed
- **Resilience** — MQTT auto-reconnect, Last Will offline status, telemetry heartbeats, persistent identity across reboots, systemd readiness/watchdog
- **Least-privilege security** — device policy scoped to the device's own thing, provisioning-only claim policy, SSE-KMS encrypted TLS-only versioned OTA bucket, all managed by Terraform
- **Release tooling** — `publish_release.py` builds a deterministic package, hashes it, uploads it, re-verifies the upload, and creates the IoT Job with rollout and abort configs

## Architecture

```
AWS Cloud                                  Edge Device
----------                                 -----------
Terraform manages:                         device-agent (Python):
  - Thing Group                              1. Connect with claim cert
  - IoT Policies                MQTT/TLS     2. Request new certificate
  - Provisioning Template      <-------->    3. RegisterThing (template)
  - S3 OTA bucket                             4. Save permanent identity
                                              5. Reconnect as the Thing

IoT Jobs -------------------------->
(OTA deployment)                           OTA Handler:
                                              download -> verify -> extract
Telemetry <--------------------------        -> activate -> health check
```

### Provisioning flow (first boot)

1. Device generates a serial number and connects as `claim-<serial>` using the fleet claim certificate.
2. Publishes to `$aws/certificates/create/json` to generate a new key pair and certificate.
3. Publishes to the provisioning template's registration topic:

```
   $aws/provisioning-templates/<template>/provision/json
```

   The template registers the Thing, activates the certificate, attaches the policy, and adds it to the Thing Group.
4. Reconnects using the permanent device certificate — the claim cert never touches the device again.
5. Credentials are saved to `certs/` and persist across reboots, so provisioning only happens once.

### OTA flow

Releases are published with `publish_release.py`, which produces a job document like:

```json
{
  "version": "1.2.0",
  "packageUrl": "https://<ota-bucket>.s3.amazonaws.com/packages/1.2.0.tar.gz?X-Amz-...",
  "packageS3Uri": "s3://<ota-bucket>/packages/1.2.0.tar.gz",
  "checksum": "<sha256-hex>",
  "rollbackVersion": "1.1.0"
}
```

The agent validates the document (the `version` is treated as a label, never a path), downloads the package, verifies the checksum, extracts it into a staging directory (rejecting links, device nodes, and path escapes), activates it with an atomic symlink swap, and runs a health check.

By default the package is downloaded over HTTPS from the presigned `packageUrl`. When `OTA_ROLE_ALIAS` is set, the agent instead prefers `packageS3Uri` and fetches it through the IoT credential provider, so there is no URL expiry.

On a successful activation the agent does **not** report `SUCCEEDED` immediately. It arms the boot guard, restarts, and reports `SUCCEEDED` only after the new build has come up and passed its health check. If the new build never confirms, `ota-boot-guard.sh` rolls back to the previous version after 3 unconfirmed boots. If the update fails before activation completes, the agent reports `FAILED` and rolls back itself.

```bash
./publish_release.py --version 1.4.0 --build-dir ./dist/edge-agent --dry-run   # show every command
./publish_release.py --version 1.4.1 --build-dir ./dist/edge-agent \
    --canary --thing-arn <arn>                                                  # one device, abort on first failure
```

Presigned URLs cap at 7 days, so a device that is offline longer than that receives a job it cannot download through `packageUrl`. Setting `OTA_ROLE_ALIAS` avoids this.

## Repository structure

```
aws-iot-secure-edge-fleet/
├── infrastructure/          # Terraform — all cloud resources (every .tf file is one module)
│   ├── providers.tf         # AWS provider
│   ├── variables.tf         # region, environment, project_name (validated)
│   ├── main.tf              # Thing Group, provisioning template, claim policy
│   ├── hardening.tf         # device policy, provisioning role, KMS-encrypted OTA bucket, publisher policy
│   ├── release-path.tf      # device OTA-read role + IoT role alias
│   └── outputs.tf           # Names/ARNs needed by the agent
├── device-agent/
│   ├── agent.py             # Provisioning, Jobs listener, boot guard, telemetry loop
│   ├── ota_handler.py       # Download/verify/extract/activate/rollback
│   ├── s3_fetch.py          # Credential-provider S3 download (no URL expiry)
│   ├── requirements.txt     # awsiotsdk
│   ├── certs/               # AmazonRootCA1.pem is vendored; device/claim keys are gitignored
│   ├── deploy/
│   │   ├── edge-agent.service   # systemd unit (unprivileged user, watchdog, boot guard)
│   │   └── ota-boot-guard.sh    # local rollback for a release that cannot start
│   └── tests/               # pytest suite for ota_handler.py and s3_fetch.py
├── publish_release.py       # package -> hash -> upload -> verify -> create job
├── .github/workflows/ci.yml # terraform fmt/validate + pytest on Python 3.9/3.11/3.12
└── LICENSE                  # MIT
```

## Getting started

**Prerequisites:**

- An AWS account with IoT Core enabled, and credentials configured for the AWS CLI
- IAM permissions to create IoT things/policies/certificates, an S3 bucket, and to run Terraform in your account
- Terraform ≥ 1.5
- Python ≥ 3.9

**1. Deploy infrastructure**

```bash
cd infrastructure
terraform init
terraform apply -var="environment=dev"
terraform output   # note the provisioning template and claim policy names
```

**2. Create the fleet claim certificate**

```bash
aws iot create-keys-and-certificate \
  --set-as-active \
  --certificate-pem-outfile claim-certificate.pem \
  --private-key-outfile claim-private.key

aws iot attach-policy \
  --policy-name <claim_policy_name> \
  --target <claimCertificateArn>
```

Place `claim-certificate.pem`, `claim-private.key`, and `AmazonRootCA1.pem` in `device-agent/certs/`.

**3. Run the agent**

```bash
cd device-agent
pip install -r requirements.txt
export IOT_ENDPOINT=$(aws iot describe-endpoint --endpoint-type iot:Data-ATS --query endpointAddress --output text)
python agent.py
```

First boot provisions the device. Every boot after that reconnects instantly using the saved identity.

**4. Run it as a service (recommended)**

`deploy/edge-agent.service` runs the agent as an unprivileged `edge-agent` user, restarts it on failure, and runs `ota-boot-guard.sh` before every start. It expects the active release at `/var/lib/edge-agent/packages/current/bin/agent`, so each release package must contain an executable at `bin/agent`. The unit and the guard must agree on the state directory (`/var/lib/edge-agent` by default, override with `OTA_STATE_DIR` in **both**).

The unit uses `Type=notify` with `WatchdogSec=120`; the agent sends `READY=1` once connected and subscribed, so `TimeoutStartSec=180` is set to cover first-boot provisioning.

## Telemetry

The agent publishes a heartbeat every 30s to `secure-edge-fleet/telemetry/<thingName>`:

```json
{ "thingName": "secure-edge-fleet-a1b2c3d4", "status": "online", "timestamp": 1727430000 }
```

## Configuration

All configuration is read from the environment.

| Variable | Default | Purpose |
|---|---|---|
| `IOT_ENDPOINT` | a placeholder endpoint compiled into `agent.py` | Your account's IoT data endpoint. **Always set this** — the agent logs a warning when it falls back to the default. |
| `PROVISIONING_TEMPLATE` | `secure-edge-fleet-prov-template` | Must match the Terraform provisioning template. |
| `CERTS_DIR` | `certs` | Where claim and device credentials live. |
| `OTA_STATE_DIR` | `/var/lib/edge-agent` | Where the boot guard's `pending` / `boot_count` files live. Must match the guard script. |
| `OTA_HEALTH_CHECK_CMD` | *(unset)* | Command that must exit 0 for a build to count as healthy. Unset, the default check only verifies that `current` points at a non-empty release. |
| `LOG_LEVEL` | `INFO` | Standard Python level names. |
| `LOG_FORMAT` | *(text)* | Set to `json` for one JSON object per line. |

The device serial is generated once on first boot (hardware serial when the platform exposes one, otherwise 64 random bits), persisted to `certs/serial`, and sent to the template as `SerialNumber`.

Packages are installed under `packages/` relative to the working directory, which is why the systemd unit sets `WorkingDirectory=/var/lib/edge-agent`.

## Testing

```bash
cd device-agent
pip install pytest pytest-cov
pytest
```

The suite covers `ota_handler.py` (66 tests, including path-traversal, link-member, checksum, size-cap, atomic-activation and rollback cases). `agent.py` is not yet covered by automated tests.

## Security notes

**Already in place:** required and validated SHA-256; `version` validated as a label before it touches a path; staged extraction that refuses link members, device nodes and path escapes; atomic activation and state writes; HTTPS-only size-capped downloads; a device IoT policy scoped to the connecting thing (`${iot:Connection.Thing.ThingName}`); a provisioning role limited to what the template does; an SSE-KMS encrypted, TLS-only, versioned OTA bucket with `force_destroy` enabled only when `environment = "dev"`; private keys created at `0600`.

**Still open:**

- **Integrity is not authenticity.** The checksum travels in the same job document as the URL, so anyone who can call `iot:CreateJob` in this account can push an arbitrary package with a matching checksum to every targeted device. `hardening.tf` grants the publisher role write access to a `signatures/` prefix, but nothing signs or verifies a manifest yet. Until that exists, keep `iot:CreateJob` tightly held and attach the publisher policy only to CI, never to a human.
- The claim certificate is a bootstrap credential shared by the fleet: restrict its policy and rotate it.
- Object Lock on the OTA bucket can only be enabled at creation; see the note in `hardening.tf`.
- Device certificates and keys are gitignored; keep `certs/` out of version control.

Updating the device policy creates a new policy version that takes effect immediately for every device using it. Roll it to a canary device first.

## Roadmap

- Sign release manifests and verify them on the device
- Automated tests for `agent.py` (boot guard state machine, deferred `SUCCEEDED`, resubscribe on resume)
- Watchdog heartbeat tied to the main loop, so a stuck loop stops feeding systemd
- Device Defender integration and dashboards
- Fleet indexing and dynamic Thing Groups
- IoT Core logging and an alarm on failed job rollouts
- Docker packaging

## License

MIT — see [LICENSE](LICENSE)
