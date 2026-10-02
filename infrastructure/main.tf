--------------------------------------------------------------
Global Identity and Locals
--------------------------------------------------------------
data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  iot_arn    = "arn:aws:iot:${var.aws_region}:${local.account_id}"
}

--------------------------------------------------------------
Basic IoT Core resources
--------------------------------------------------------------

resource "aws_iot_thing_group" "edge_fleet" {
  name = "${var.project_name}-fleet"

  properties {
    attribute_payload {
      attributes = {
        environment = var.environment
        type        = "edge-device"
      }
    }
  }
}

--------------------------------------------------------------
Device Security
--------------------------------------------------------------

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
        Action = ["iot:Subscribe"]
        Resource = ["${local.iot_arn}:topicfilter/$aws/things/$${iot:Connection.Thing.ThingName}/jobs/*"]
      },
      {
        Sid    = "OwnJobExecutionsOnly"
        Effect   = "Allow"
        Action = [
          "iot:DescribeJobExecution",
          "iot:GetPendingJobExecutions",
          "iot:StartNextPendingJobExecution",
          "iot:UpdateJobExecution"
        ]
        Resource = ["${local.iot_arn}:thing/$${iot:Connection.Thing.ThingName}"]
      },
      {
        Sid      = "AssumeOtaReadRole"
        Effect   = "Allow"
        Action = ["iot:AssumeRoleWithCertificate"]
        Resource = ["${local.iot_arn}:rolealias/${var.project_name}-device-ota-read"]
      }
    ]
  })
}

--------------------------------------------------------------
Fleet Provisioning
--------------------------------------------------------------

resource "aws_iam_role" "fleet_provisioning" {
  name = "${var.project_name}-fleet-provisioning-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "iot.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

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
          "iot:CreateThing", "iot:DescribeThing", "iot:UpdateThing",
          "iot:AddThingToThingGroup", "iot:RemoveThingFromThingGroup",
          "iot:ListThingGroupsForThing", "iot:ListPrincipalThings",
          "iot:AttachThingPrincipal", "iot:DetachThingPrincipal"
        ]
        Resource = ["${local.iot_arn}:thing/${var.project_name}-*"]
      },
      {
        Sid    = "ManageCertificates"
        Effect = "Allow"
        Action = ["iot:RegisterCertificate", "iot:DescribeCertificate", "iot:UpdateCertificate"]
        Resource = ["${local.iot_arn}:cert/*"]
      },
      {
        Sid    = "AttachTheDevicePolicyOnly"
        Effect   = "Allow"
        Action = ["iot:AttachPolicy", "iot:ListAttachedPolicies"]
        Resource = ["${local.iot_arn}:policy/${var.project_name}-device-policy"]
      },
      {
        Sid    = "ReadTheFleetGroup"
        Effect = "Allow"
        Action = ["iot:DescribeThingGroup", "iot:ListThingGroups"]
        Resource = ["${local.iot_arn}:thinggroup/${var.project_name}-fleet"]
      },
      {
        Sid    = "RegisterAgainstTheTemplate"
        Effect   = "Allow"
        Action = ["iot:RegisterThing"]
        Resource = ["${local.iot_arn}:provisioningtemplate/${var.project_name}-prov-template"]
      }
    ]
  })
}

resource "aws_iot_provisioning_template" "edge_fleet" {
  name                  = "${var.project_name}-prov-template"
  description           = "Provisioning template for secure edge fleet devices"
  enabled               = true
  provisioning_role_arn = aws_iam_role.fleet_provisioning.arn

  template_body = jsonencode({
    Parameters = { SerialNumber = { Type = "String" } }
    Resources = {
      thing = {
        Type = "AWS::IoT::Thing"
        Properties = {
          ThingName = { "Fn::Join" = ["", ["${var.project_name}-", { "Ref" = "SerialNumber" }]] }
          AttributePayload = {
            serialNumber = { "Ref" = "SerialNumber" }
            environment  = var.environment
          }
          ThingGroups = [aws_iot_thing_group.edge_fleet.name]
        }
      }
      certificate = {
        Type = "AWS::IoT::Certificate"
        Properties = {
          CertificateId = { "Ref" = "AWS::IoT::Certificate::Id" }
          Status        = "Active"
        }
      }
      policy = {
        Type = "AWS::IoT::Policy"
        Properties = { PolicyName = aws_iot_policy.device_policy.name }
      }
    }
  })
}

resource "aws_iot_policy" "claim_policy" {
  name = "${var.project_name}-claim-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["iot:Connect"]
        Resource = ["arn:aws:iot:${var.aws_region}::client/claim-"]
      },
      {
        Effect = "Allow"
        Action = ["iot:Publish", "iot:Receive"]
        Resource = [
          "arn:aws:iot:${var.aws_region}::topic/$aws/certificates/create/",
          "arn:aws:iot:${var.aws_region}::topic/$aws/provisioning-templates/${var.project_name}-prov-template/provision/"
        ]
      },
      {
        Effect = "Allow"
        Action = ["iot:Subscribe"]
        Resource = [
          "arn:aws:iot:${var.aws_region}::topicfilter/$aws/certificates/create/",
          "arn:aws:iot:${var.aws_region}::topicfilter/$aws/provisioning-templates/${var.project_name}-prov-template/provision/"
        ]
      }
    ]
  })
}

--------------------------------------------------------------
OTA Supply Chain
--------------------------------------------------------------

data "aws_iam_policy_document" "ota_kms_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["${data.aws_caller_identity.current.arn}"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "ota" {
  description             = "Encryption for ${var.project_name} OTA packages"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.ota_kms_policy.json
}

resource "aws_kms_alias" "ota" {
  name          = "alias/${var.project_name}-ota"
  target_key_id = aws_kms_key.ota.key_id
}

resource "aws_s3_bucket" "ota_packages" {
  bucket = "${var.project_name}-ota-packages-${var.environment}"
  force_destroy = var.environment == "dev"
}

resource "aws_s3_bucket_versioning" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
  rule { object_ownership = "BucketOwnerEnforced" }
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
      Resource = [aws_s3_bucket.ota_packages.arn, "${aws_s3_bucket.ota_packages.arn}/*"]
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

resource "aws_iam_policy" "ota_publisher" {
  name        = "${var.project_name}-ota-publisher"
  description = "Write OTA releases only. Attach to the CI role, never to a human."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishReleases"
        Effect   = "Allow"
        Action = ["s3:PutObject", "s3:AbortMultipartUpload"]
        Resource = ["${aws_s3_bucket.ota_packages.arn}/packages/*"]
      },
      {
        Sid      = "PublishSignatures"
        Effect   = "Allow"
        Action = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.ota_packages.arn}/signatures/*"]
      },
      {
        SId      = "EncryptWithOurKey"
        Effect   = "Allow"
        Action = ["kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = [aws_kms_key.ota.arn]
      }
    ]
  })
}

--------------------------------------------------------------
Observability (Logging & Telemetry)
--------------------------------------------------------------

resource "aws_cloudwatch_log_group" "iot_core" {
  name              = "/aws/iot/${var.project_name}-core"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.ota.arn
}

resource "aws_iam_role" "iot_logging" {
  name = "${var.project_name}-iot-logging-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "iot.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "iot_logging" {
  name = "${var.project_name}-iot-logging-policy"
  role = aws_iam_role.iot_logging.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.iot_core.arn}:*"]
    }]
  })
}

resource "aws_iot_logging_options" "core" {
  role_arn = aws_iam_role.iot_logging.arn
  default_log_level = "INFO"
}

resource "aws_iot_topic_rule" "telemetry_route" {
  name        = "secure_edge_fleet_telemetry_route"
  description = "Route device telemetry to CloudWatch Logs"
  enabled     = true
  sql         = "SELECT * FROM 'secure-edge-fleet/telemetry/+'"
  sql_version = "2016-03-23"

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.iot_core.name
    role_arn       = aws_iam_role.iot_logging.arn
  }
}

--------------------------------------------------------------
Monitoring (Dead Man's Switch)
--------------------------------------------------------------

resource "aws_sns_topic" "fleet_alerts" {
  name = "${var.project_name}-fleet-alerts"
}

resource "aws_cloudwatch_log_metric_filter" "telemetry_heartbeat" {
  name           = "TelemetryHeartbeat"
  pattern        = "{ $.status = \"online\" }"
  log_group_name = aws_cloudwatch_log_group.iot_core.name

  metric_transformation {
    name      = "HeartbeatCount"
    namespace = "SecureEdgeFleet"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "device_offline" {
  alarm_name          = "${var.project_name}-device-offline"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "HeartbeatCount"
  namespace           = "SecureEdgeFleet"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.fleet_alerts.arn]
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "${var.project_name}-logs-${var.environment}"
}

resource "aws_s3_bucket_ownership_controls" "log_bucket_oc" {
  bucket = aws_s3_bucket.log_bucket.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_acl" "log_bucket_acl" {
  bucket = aws_s3_bucket.log_bucket.id
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "ota_logging" {
  bucket = aws_s3_bucket.ota_packages.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

resource "aws_s3_bucket_notification" "ota_notification" {
  bucket = aws_s3_bucket.ota_packages.id
  topic {
    topic_arn     = aws_sns_topic.fleet_alerts.arn
    events        = ["s3:ObjectCreated:*"]
  }
}
