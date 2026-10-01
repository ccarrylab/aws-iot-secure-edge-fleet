# ---------------------------------------------------------------------------
# hardening.tf  —  drop-in replacements / additions for infrastructure/
#
# These replace the matching resources in main.tf. Copy the blocks over the
# originals: the resource addresses are unchanged, so `terraform plan` shows an
# in-place update rather than a destroy/create.
#
# ⚠️ Updating aws_iot_policy.device_policy creates a NEW policy version, and
# that takes effect immediately for every device already using it. Roll it to a
# canary device first and confirm it can still connect, publish telemetry and
# receive a Job before you roll it wider.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  iot_arn    = "arn:aws:iot:${var.aws_region}:${local.account_id}"
}

# ---------------------------------------------------------------------------
# C4 — device policy, scoped to the connecting device's own thing
#
# The previous version used a wildcard in the identity position
# (client/${var.project_name}-*, topic/${var.project_name}/*), so any device
# could connect AS another device, read the whole fleet's telemetry, and reach
# $aws/things/<someone-else>/jobs/*.
#
# NOTE: ${iot:Connection.Thing.ThingName} resolves from the certificate's
# thing attachment, which the provisioning template already makes via
# iot:AttachThingPrincipal. The agent must connect with its thing name as the
# client id — it already does.
# NOTE: in Terraform, $${...} is an ESCAPED literal ${, which is what we want
# for IoT policy variables. Do not "fix" these to single $.
# ---------------------------------------------------------------------------
resource "aws_iot_policy" "device_policy" {
  name = "${var.project_name}-device-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ConnectAsOwnThingOnly"
        Effect   = "Allow"
        Action   = ["iot:Connect"]
        Resource = ["${local.iot_arn}:client/$${iot:Connection.Thing.ThingName}"]
      },
      {
        Sid    = "OwnTelemetryAndJobsOnly"
        Effect = "Allow"
        Action = ["iot:Publish", "iot:Receive"]
        Resource = [
          "${local.iot_arn}:topic/${var.project_name}/telemetry/$${iot:Connection.Thing.ThingName}",
          "${local.iot_arn}:topic/$aws/things/$${iot:Connection.Thing.ThingName}/jobs/*"
        ]
      },
      {
        Sid      = "SubscribeToOwnJobsOnly"
        Effect   = "Allow"
        Action   = ["iot:Subscribe"]
        Resource = ["${local.iot_arn}:topicfilter/$aws/things/$${iot:Connection.Thing.ThingName}/jobs/*"]
      },
      {
        # Resource = "*" here previously let any device update ANY job
        # execution in the account — including marking other devices'
        # executions SUCCEEDED while they sat on old firmware.
        Sid    = "OwnJobExecutionsOnly"
        Effect = "Allow"
        Action = [
          "iot:DescribeJobExecution",
          "iot:GetPendingJobExecutions",
          "iot:StartNextPendingJobExecution",
          "iot:UpdateJobExecution"
        ]
        Resource = ["${local.iot_arn}:thing/$${iot:Connection.Thing.ThingName}"]
      },
      {
        # Lets the device exchange its OWN certificate for short-lived IAM
        # credentials, which it then uses to read its release object from S3.
        # This is what removes the 7-day presigned-URL expiry: nothing is
        # presigned, so an offline device can still update weeks later.
        #
        # Scoped to the single role alias. Without this statement the agent
        # gets AccessDenied from the credential provider and no OTA at all.
        Sid      = "AssumeOtaReadRole"
        Effect   = "Allow"
        Action   = ["iot:AssumeRoleWithCertificate"]
        Resource = ["${local.iot_arn}:rolealias/${var.project_name}-device-ota-read"]
      }
    ]
  })
}

# NOTE: the shadow permissions (iot:GetThingShadow / UpdateThingShadow /
# DeleteThingShadow) are intentionally omitted — neither agent.py nor
# ota_handler.py ever touches a device shadow. If you implement version
# reporting via the shadow, add a statement scoped to:
#   ${local.iot_arn}:thing/$${iot:Connection.Thing.ThingName}
# Using shadow topics:
#   ${local.iot_arn}:topic/$aws/things/$${iot:Connection.Thing.ThingName}/shadow/*

# ---------------------------------------------------------------------------
# H5 — the provisioning role, scoped to what the template actually does
#
# Removed: iot:CreatePolicy, iot:AttachPrincipalPolicy (deprecated, unused),
# iot:GetPolicy, iot:ListPolicyPrincipals, iot:ListPrincipalPolicies,
# iot:CreateCertificateFromCsr (this template has no CSR parameter).
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "fleet_provisioning" {
  name = "${var.project_name}-fleet-provisioning-policy"
  role = aws_iam_role.fleet_provisioning.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageOnlyOurThingNamespace"
        Effect = "Allow"
        Action = [
          "iot:CreateThing",
          "iot:DescribeThing",
          "iot:UpdateThing",
          "iot:AddThingToThingGroup",
          "iot:RemoveThingFromThingGroup",
          "iot:ListThingGroupsForThing",
          "iot:ListPrincipalThings",
          "iot:AttachThingPrincipal",
          "iot:DetachThingPrincipal"
        ]
        Resource = ["${local.iot_arn}:thing/${var.project_name}-*"]
      },
      {
        Sid    = "ManageCertificates"
        Effect = "Allow"
        Action = [
          "iot:RegisterCertificate",
          "iot:DescribeCertificate",
          "iot:UpdateCertificate"
        ]
        Resource = ["${local.iot_arn}:cert/*"]
      },
      {
        Sid      = "AttachTheDevicePolicyOnly"
        Effect   = "Allow"
        Action   = ["iot:AttachPolicy", "iot:ListAttachedPolicies"]
        Resource = ["${local.iot_arn}:policy/${var.project_name}-device-policy"]
      },
      {
        Sid      = "ReadTheFleetGroup"
        Effect   = "Allow"
        Action   = ["iot:DescribeThingGroup", "iot:ListThingGroups"]
        Resource = ["${local.iot_arn}:thinggroup/${var.project_name}-fleet"]
      },
      {
        Sid      = "RegisterAgainstTheTemplate"
        Effect   = "Allow"
        Action   = ["iot:RegisterThing"]
        Resource = ["${local.iot_arn}:provisioningtemplate/${var.project_name}-prov-template"]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# H8 — the OTA bucket, treated as a supply chain rather than a scratch dir
# ---------------------------------------------------------------------------
resource "aws_kms_key" "ota" {
  #checkov:skip=CKV2_AWS_64:Relies on the default key policy - tighten for production
  description             = "Encryption for ${var.project_name} OTA packages"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "ota" {
  # The alias the publish tooling refers to ("alias/<project>-ota").
  # Without this the key exists but nothing can name it, and
  # `publish_release.py --kms-key alias/...` fails with NotFoundException.
  # An alias also survives key rotation; a raw key id does not.
  name          = "alias/${var.project_name}-ota"
  target_key_id = aws_kms_key.ota.key_id
}

resource "aws_s3_bucket" "ota_packages" {
  #checkov:skip=CKV_AWS_18:Dev fleet - add a logging bucket before production
  #checkov:skip=CKV_AWS_144:Single-region dev bucket - enable cross-region replication for production
  #checkov:skip=CKV2_AWS_62:Nothing consumes bucket events yet
  bucket = "${var.project_name}-ota-packages-${var.environment}"

  # was: force_destroy = true (hardcoded) — a `terraform destroy` in prod would
  # have deleted every firmware release you own.
  force_destroy = var.environment == "dev"

  # Object Lock can only be enabled at bucket creation. If you want immutable
  # releases (and you should, for a firmware store), add object_lock_enabled
  # = true here — but that means recreating the bucket.
  # object_lock_enabled = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ota.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id
  rule { object_ownership = "BucketOwnerEnforced" } # ACLs disabled entirely
}

resource "aws_s3_bucket_policy" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.ota_packages.arn,
        "${aws_s3_bucket.ota_packages.arn}/*"
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id

  rule {
    id     = "expire-old-releases"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

# A publisher role with write access only to the prefix the script uploads to
# (packages/). Nothing in the repo currently says who may publish a release,
# which in practice means "whoever runs the script with their own credentials".
resource "aws_iam_policy" "ota_publisher" {
  name        = "${var.project_name}-ota-publisher"
  description = "Write OTA releases only. Attach to the CI role, never to a human."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishReleases"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = ["${aws_s3_bucket.ota_packages.arn}/packages/*"]
      },
      {
        Sid      = "PublishSignatures"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.ota_packages.arn}/signatures/*"]
      },
      {
        Sid      = "EncryptWithOurKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = [aws_kms_key.ota.arn]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Variable hygiene — additions for variables.tf
#
# Without these, `-var="environment=prod"` produced a production-labelled
# environment with dev-grade destructive settings (force_destroy = true).
# ---------------------------------------------------------------------------
/*
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must look like us-east-1."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "secure-edge-fleet"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,30}$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens (3-31 chars)."
  }
}
*/

# ---------------------------------------------------------------------------
# Still missing, and worth adding next:
#   - aws_iot_logging_options   (IoT Core logging is OFF by default — when C4
#                                bites, this is the audit trail you'll want.
#                                Needs a role that can write to CloudWatch Logs.)
#   - an EventBridge rule on IoT job terminal states, feeding a CloudWatch
#     alarm on failures — a failed rollout across 400 devices otherwise
#     produces no signal at all.
#   - aws_iot_topic_rule to route telemetry somewhere (today it is published
#     into the void).
#   - aws_iot_thing_type for registry-level attribute validation.
# ---------------------------------------------------------------------------
