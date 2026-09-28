# ---------------------------------------------------------------------------
# Release path: device-side access to OTA packages via the AWS IoT Core
# credential provider.
#
# PROBLEM THIS SOLVES
#   publish_release.py hands the device a *presigned* S3 URL. SigV4 presigned
#   URLs cap at 7 days, so a device that is offline longer than that receives a
#   job it can never download - and the failure looks like a network problem,
#   not an expired URL.
#
# WHAT REPLACES IT
#   The device authenticates to the credential provider with its OWN X.509
#   certificate (mutual TLS, over HTTPS) and receives short-lived IAM
#   credentials. It then reads the object from S3 with a normal SigV4 request,
#   which boto3 handles. Nothing is presigned, so nothing expires - a device
#   can be offline for a month and still update.
#
# The credential provider endpoint is:
#   https://<iot-endpoint>/role-aliases/<alias>/credentials
# with header:  x-amzn-iot-thingname: <thing name>
# (Confirmed against the AWS IoT Core developer guide, "Authorizing direct
# calls to AWS services".)
# ---------------------------------------------------------------------------

variable "publisher_role_name" {
  description = <<-EOT
    Name (not ARN) of the IAM role your build/CI publishes as - the role that
    runs publish_release.py. Leave empty to skip the attachment; set it to
    grant that role the rights to write OTA objects and read the signing key.
    This policy is designed to attach to a pipeline role, never to a human.
  EOT
  type        = string
  default     = ""
}

variable "device_credential_duration" {
  description = <<-EOT
    Lifetime in seconds of the credentials a device receives. 3600 is the
    default and is plenty: the agent only needs them for one download, and
    short-lived credentials limit the blast radius of a stolen device.
    Must be <= the IAM role's max_session_duration.
  EOT
  type        = number
  default     = 3600
}

# ---------------------------------------------------------------------------
# H9 - the role a device assumes to read its own release object
# ---------------------------------------------------------------------------

resource "aws_iam_role" "device_ota_read" {
  name        = "${var.project_name}-device-ota-read"
  description = "Assumed by devices via the IoT credential provider to read OTA packages. Read-only."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "credentials.iot.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "device_ota_read" {
  name = "${var.project_name}-device-ota-read"
  role = aws_iam_role.device_ota_read.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadReleaseObjectsOnly"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = [
          "${aws_s3_bucket.ota_packages.arn}/packages/*"
        ]
      },
      {
        # REQUIRED, and easy to miss: the bucket is configured with SSE-KMS
        # (aws_s3_bucket_server_side_encryption_configuration above). Without
        # kms:Decrypt the S3 GET fails with AccessDenied, and the error names
        # S3 rather than the key, which sends you looking in the wrong place.
        Sid      = "DecryptReleaseObjects"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.ota.arn]
      }
    ]
  })
}

resource "aws_iot_role_alias" "device_ota" {
  alias               = "${var.project_name}-device-ota-read"
  role_arn            = aws_iam_role.device_ota_read.arn
  credential_duration = var.device_credential_duration
}

# ---------------------------------------------------------------------------
# H10 - attach the publisher policy to the build role
#
# aws_iam_policy.ota_publisher is created by hardening.tf but attached to
# nothing, so publish_release.py has no rights until this runs. Gated on the
# variable so the plan stays clean when the role name is not known yet.
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy_attachment" "ota_publisher" {
  count = var.publisher_role_name == "" ? 0 : 1

  role       = var.publisher_role_name
  policy_arn = aws_iam_policy.ota_publisher.arn
}

output "device_ota_read_role_arn" {
  description = "Role devices assume for OTA reads (for auditing, not for the agent)"
  value       = aws_iam_role.device_ota_read.arn
}

output "device_ota_role_alias" {
  description = "Pass to the agent as OTA_ROLE_ALIAS"
  value       = aws_iot_role_alias.device_ota.alias
}

output "ota_publisher_attached" {
  description = "True once the publisher policy is attached to your build role"
  value       = length(aws_iam_role_policy_attachment.ota_publisher) > 0
}
