# --------------------------------------------------------------
# Global Identity and Locals
# --------------------------------------------------------------
data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  iot_arn    = "arn:aws:iot:${var.aws_region}:${local.account_id}"
}

# --------------------------------------------------------------
# Basic IoT Core resources
# --------------------------------------------------------------

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

# --------------------------------------------------------------
# Device Security
# --------------------------------------------------------------

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
        Sid      = "AssumeOtaReadRole"
        Effect   = "Allow"
        Action = ["iot:AssumeRoleWithCertificate"]
        Resource = ["${local.iot_arn}:rolealias/${var.project_name}-device-ota-read"]
      }
    ]
  })
}

# --------------------------------------------------------------
# Fleet Provisioning
# --------------------------------------------------------------

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
        Resource = ["arn:aws:iot:${var.aws_region}:*:client/claim-*"]
      },
      {
        Effect = "Allow"
        Action = ["iot:Publish", "iot:Receive"]
        Resource = [
          "arn:aws:iot:${var.aws_region}:*:topic/$aws/certificates/create/*",
          "arn:aws:iot:${var.aws_region}:*:topic/$aws/provisioning-templates/${var.project_name}-prov-template/provision/*"
        ]
      },
      {
        Effect = "Allow"
        Action = ["iot:Subscribe"]
        Resource = [
          "arn:aws:iot:${var.aws_region}:*:topicfilter/$aws/certificates/create/*",
          "arn:aws:iot:${var.aws_//L_D_S_L_L} a la l'unisson", "target_bucket" : aws_s3_bucket.log_bucket.id}
