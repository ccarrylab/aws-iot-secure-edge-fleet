
# 🔐 AWS IoT Secure Edge Fleet

**Zero-touch provisioning · Safe OTA with auto-rollback · Built with Terraform + Python**

[![Terraform](https://img.shields.io/badge/Terraform-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![AWS IoT](https://img.shields.io/badge/AWS-IoT-FF9900?logo=amazon-aws&logoColor=white)](https://aws.amazon.com/iot/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)


---

## ✨ Features

| | |
|---|---|
| 🔑 **Zero-touch provisioning** | Devices ship with a one-time claim certificate and exchange it for a unique, permanent X.509 certificate on first boot — no manual work per device. |
| ⬆️ **Safe OTA updates** | AWS IoT Jobs delivery, SHA-256 verification, versioned installs, atomic symlink activation, health check, and **automatic rollback** on failure. |
| 💪 **Resilience** | MQTT auto-reconnect, telemetry heartbeats, and persistent identity across reboots. |
| 🔒 **Least-privilege security** | Scoped IoT policies, provisioning-only claim policy, private versioned OTA bucket — all managed by Terraform. |

## 🏗️ Architecture

```
┌──────────────────────┐          ┌──────────────────────────────┐
│  AWS Cloud           │          │  Edge Device                 │
│  ─────────           │          │  ───────────                 │
│  Terraform:          │   MQTT   │  device-agent (Python)       │
│   · Thing Group      │  ◄────►  │  1️⃣ Connect w/ claim cert    │
│   · IoT Policies     │   TLS    │  2️⃣ Request new certificate  │
│   · Prov. Template   │          │  3️⃣ RegisterThing (template) │
│   · S3 OTA bucket    │          │  4️⃣ Save permanent identity  │
│                      │          │  5️⃣ Reconnect as the Thing   │
│  IoT Jobs ───────────┼────────► │                              │
│  (OTA deployment)    │          │  OTA Handler:                │
│                      │          │  download → verify → extract │
│  Telemetry ◄─────────┼───────── │  → activate → health check   │
└──────────────────────┘          └──────────────────────────────┘
```

### 🔑 Provisioning flow (first boot)

1. Generates a serial number and connects as `claim-&lt;serial&gt;` with the fleet claim certificate
2. Publishes to `$aws/certificates/create/json` to generate a key pair + certificate
3. Publishes to `$aws/provisioning-templates/&lt;template&gt;/provision/json` — the template registers the Thing, activates the cert, attaches the policy, and adds it to the Thing Group
4. Reconnects with the **permanent device certificate** (the claim cert can never operate the device)
5. Credentials persist in `certs/` across reboots — no re-provisioning, ever

### ⬆️ OTA flow

Create an IoT Job with a document like:

```json
{
  "version": "1.2.0",
  "packageUrl": "https://&lt;ota-bucket&gt;.s3.amazonaws.com/releases/app-1.2.0.tar.gz",
  "checksum": "&lt;sha256-hex&gt;",
  "rollbackVersion": "1.1.0"
}
```

The agent then runs: **download → SHA-256 verify → extract (path-traversal guarded) → activate via symlink → health check** → reports `SUCCEEDED`, or reports `FAILED` and **automatically rolls back**.

## 📁 Repository structure

```
aws-iot-secure-edge-fleet/
├── infrastructure/        # Terraform — all cloud resources
│   ├── providers.tf       # AWS provider
│   ├── variables.tf       # region, environment, project_name
│   ├── main.tf            # Thing Group, policies, S3, provisioning template
│   └── outputs.tf         # Names/ARNs needed by the agent
├── device-agent/
│   ├── agent.py           # Provisioning, Jobs listener, telemetry loop
│   ├── ota_handler.py     # Download/verify/extract/activate/rollback
│   └── requirements.txt   # awsiotsdk, boto3, requests
└── LICENSE                # MIT
```

## 🚀 Getting started

**Prerequisites:** AWS CLI · Terraform ≥ 1.3 · Python ≥ 3.9

**1. Deploy infrastructure**

```bash
cd infrastructure
terraform init
terraform apply -var="environment=dev"
terraform output   # note the provisioning template name & IoT endpoint
```

**2. Create the fleet claim certificate**

```bash
aws iot create-keys-and-certificate \
  --set-as-active \
  --certificate-pem-outfile claim-certificate.pem \
  --private-key-outfile claim-private.key

aws iot attach-policy \
  --policy-name &lt;claim_policy_name&gt; \
  --target &lt;claimCertificateArn&gt;
```

Place `claim-certificate.pem`, `claim-private.key`, and `AmazonRootCA1.pem` in `device-agent/certs/`.

**3. Run the agent**

```bash
cd device-agent
pip install -r requirements.txt
python agent.py
```

First boot provisions the device — every boot after that reconnects instantly with its permanent identity.

## 📡 Telemetry

Publishes a heartbeat every 30s to `secure-edge-fleet/telemetry/&lt;thingName&gt;`:

```json
{ "thingName": "secure-edge-fleet-a1b2c3d4", "status": "online", "timestamp": 1727430000 }
```

## ⚙️ Configuration

| Setting | Location | Notes |
|---|---|---|
| `IOT_ENDPOINT` | `agent.py` | Replace with your account's IoT endpoint |
| `TEMPLATE_NAME` | `agent.py` | Must match the Terraform template |
| Serial number | generated | First 8 chars of a fresh UUID, sent as `SerialNumber` |
| Health check | `OTAHandler(...)` | Defaults to symlink/dir check; override with `health_check_cmd` |

## 🔒 Security notes

- 🔑 The claim certificate is a **bootstrap credential only** — restrict and rotate it for production
- 🪣 `force_destroy = true` on the OTA bucket is for dev convenience — remove in production
- ✅ Always verify the job document checksum against the uploaded artifact
- 🚫 Device certs/keys are written `0600` — keep `certs/` out of version control

## 🛣️ Roadmap

- [ ] Pre-signed S3 URLs for package downloads
- [ ] Staged rollouts via IoT Job rollout + abort configs
- [ ] Device Defender integration & dashboards
- [ ] Fleet indexing + dynamic Thing Groups
- [ ] systemd / Docker packaging
- [ ] GitHub Actions: build → checksum → publish OTA artifacts

## 📄 License

MIT — see [LICENSE](LICENSE)
