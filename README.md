# AWS IoT Secure Edge Fleet

Zero-touch device provisioning and safe OTA updates for AWS IoT, built with Terraform and Python.

[![Terraform](https://img.shields.io/badge/Terraform-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Devices provision themselves on first boot using a shared claim certificate, then get a unique permanent identity — no manual per-device setup. OTA updates are delivered through AWS IoT Jobs, verified against a checksum, and rolled back automatically if the health check fails after install.

## Features

- **Zero-touch provisioning** — devices exchange a one-time claim certificate for a unique X.509 certificate on first boot
- **Safe OTA** — SHA-256 verification, versioned installs, atomic symlink activation, health check, automatic rollback on failure
- **Resilience** — MQTT auto-reconnect, telemetry heartbeats, persistent identity across reboots
- **Least-privilege security** — scoped IoT policies, provisioning-only claim policy, private versioned OTA bucket, all managed by Terraform

## Architecture

```
AWS Cloud                              Edge Device
----------                             -----------
Terraform manages:        MQTT/TLS     device-agent (Python)
  - Thing Group          <-------->      1. Connect with claim cert
  - IoT Policies                         2. Request new certificate
  - Provisioning Template                3. RegisterThing (template)
  - S3 OTA bucket                        4. Save permanent identity
                                          5. Reconnect as the Thing
IoT Jobs -------------------------->
  (OTA deployment)                     OTA Handler:
                                          download -> verify -> extract
Telemetry <--------------------------    -> activate -> health check
```

### Provisioning flow (first boot)

1. Device generates a serial number and connects as `claim-<serial>` using the fleet claim certificate.
2. Publishes to `$aws/certificates/create/json` to generate a new key pair and certificate.
3. Publishes to `$aws/provisioning-templates/<template>/provision/json`. The template registers the Thing, activates the certificate, attaches the policy, and adds it to the Thing Group.
4. Reconnects using the permanent device certificate — the claim cert never touches the device again.
5. Credentials are saved to `certs/` and persist across reboots, so provisioning only happens once.

### OTA flow

Create an IoT Job with a document like:

```json
{
  "version": "1.2.0",
  "packageUrl": "https://<ota-bucket>.s3.amazonaws.com/releases/app-1.2.0.tar.gz",
  "checksum": "<sha256-hex>",
  "rollbackVersion": "1.1.0"
}
```

The agent downloads the package, verifies the checksum, extracts it (guarded against path traversal), activates it via symlink swap, and runs a health check. On success it reports `SUCCEEDED`; on failure it reports `FAILED` and rolls back to the previous version automatically.

## Repository structure

```
aws-iot-secure-edge-fleet/
├── infrastructure/       # Terraform — all cloud resources
│   ├── providers.tf      # AWS provider
│   ├── variables.tf      # region, environment, project_name
│   ├── main.tf            # Thing Group, policies, S3, provisioning template
│   └── outputs.tf         # Names/ARNs needed by the agent
├── device-agent/
│   ├── agent.py            # Provisioning, Jobs listener, telemetry loop
│   ├── ota_handler.py      # Download/verify/extract/activate/rollback
│   └── requirements.txt   # awsiotsdk, boto3, requests
└── LICENSE                # MIT
```

## Getting started

Requires AWS CLI, Terraform ≥ 1.3, and Python ≥ 3.9.

**1. Deploy infrastructure**

```bash
cd infrastructure
terraform init
terraform apply -var="environment=dev"
terraform output   # note the provisioning template name and IoT endpoint
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
python agent.py
```

First boot provisions the device. Every boot after that reconnects instantly using the saved identity.

## Telemetry

The agent publishes a heartbeat every 30s to `secure-edge-fleet/telemetry/<thingName>`:

```json
{ "thingName": "secure-edge-fleet-a1b2c3d4", "status": "online", "timestamp": 1727430000 }
```

## Configuration

- `IOT_ENDPOINT` (in `agent.py`) — replace with your account's IoT endpoint
- `TEMPLATE_NAME` (in `agent.py`) — must match the Terraform provisioning template
- Serial number — generated automatically, first 8 characters of a UUID, sent as `SerialNumber`
- Health check — defaults to a symlink/directory check in `OTAHandler(...)`, override with `health_check_cmd`

## Security notes

The claim certificate is a bootstrap credential only — restrict its policy and rotate it regularly in production. `force_destroy = true` on the OTA bucket is a dev convenience; remove it before production. Always verify the job document's checksum against the uploaded artifact before activating. Device certificates and keys are written with `0600` permissions — keep `certs/` out of version control.

## Roadmap

- Pre-signed S3 URLs for package downloads
- Staged rollouts via IoT Job rollout/abort configs
- Device Defender integration and dashboards
- Fleet indexing and dynamic Thing Groups
- systemd / Docker packaging
- GitHub Actions pipeline: build → checksum → publish OTA artifacts

## License

MIT — see [LICENSE](LICENSE)
