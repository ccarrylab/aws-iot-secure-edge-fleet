#--------------------------------------------------------------
# Basic IoT Core resources
#--------------------------------------------------------------

# Thing Group for the fleet
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

# IoT Policy for devices
resource "aws_iot_policy" "device_policy" {
  name = "${var.project_name}-device-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iot:Connect",
          "iot:Publish",
          "iot:Subscribe",
          "iot:Receive",
          "iot:GetThingShadow",
          "iot:UpdateThingShadow",
          "iot:DeleteThingShadow"
        ]
        Resource = [
          "arn:aws:iot:${var.aws_region}:*:client/${var.project_name}-*",
          "arn:aws:iot:${var.aws_region}:*:topic/${var.project_name}/*",
          "arn:aws:iot:${var.aws_region}:*:topicfilter/${var.project_name}/*",
          "arn:aws:iot:${var.aws_region}:*:topic/$aws/things/*/jobs/*",
          "arn:aws:iot:${var.aws_region}:*:topicfilter/$aws/things/*/jobs/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iot:DescribeJobExecution",
          "iot:GetPendingJobExecutions",
          "iot:StartNextPendingJobExecution",
          "iot:UpdateJobExecution"
        ]
        Resource = "*"
      }
    ]
  })
}

# S3 bucket for OTA packages
resource "aws_s3_bucket" "ota_packages" {
  bucket = "${var.project_name}-ota-packages-${var.environment}"

  force_destroy = true # useful for development
}

resource "aws_s3_bucket_versioning" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "ota_packages" {
  bucket = aws_s3_bucket.ota_packages.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#--------------------------------------------------------------
# Fleet Provisioning (by Claim)
#--------------------------------------------------------------

# IAM role that Fleet Provisioning will assume
resource "aws_iam_role" "fleet_provisioning" {
  name = "${var.project_name}-fleet-provisioning-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "iot.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "fleet_provisioning" {
  name = "${var.project_name}-fleet-provisioning-policy"
  role = aws_iam_role.fleet_provisioning.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iot:AddThingToThingGroup",
          "iot:AttachPolicy",
          "iot:AttachPrincipalPolicy",
          "iot:AttachThingPrincipal",
          "iot:CreateCertificateFromCsr",
          "iot:CreatePolicy",
          "iot:CreateThing",
          "iot:DescribeCertificate",
          "iot:DescribeThing",
          "iot:DescribeThingGroup",
          "iot:DescribeThingType",
          "iot:DetachThingPrincipal",
          "iot:GetPolicy",
          "iot:ListAttachedPolicies",
          "iot:ListPolicyPrincipals",
          "iot:ListPrincipalPolicies",
          "iot:ListPrincipalThings",
          "iot:ListThingGroups",
          "iot:ListThingGroupsForThing",
          "iot:ListThingPrincipals",
          "iot:RegisterCertificate",
          "iot:RegisterThing",
          "iot:RemoveThingFromThingGroup",
          "iot:UpdateCertificate",
          "iot:UpdateThing",
          "iot:UpdateThingGroupsForThing"
        ]
        Resource = "*"
      }
    ]
  })
}

# Fleet Provisioning Template
resource "aws_iot_provisioning_template" "edge_fleet" {
  name                  = "${var.project_name}-prov-template"
  description           = "Provisioning template for secure edge fleet devices"
  enabled               = true
  provisioning_role_arn = aws_iam_role.fleet_provisioning.arn

  template_body = jsonencode({
    Parameters = {
      SerialNumber = {
        Type = "String"
      }
    }
    Resources = {
      thing = {
        Type = "AWS::IoT::Thing"
        Properties = {
          ThingName = {
            "Fn::Join" = ["", ["${var.project_name}-", { "Ref" = "SerialNumber" }]]
          }
          AttributePayload = {
            serialNumber = { "Ref" = "SerialNumber" }
            environment  = var.environment
          }
          ThingGroups = [
            aws_iot_thing_group.edge_fleet.name
          ]
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
        Properties = {
          PolicyName = aws_iot_policy.device_policy.name
        }
      }
    }
  })
}

#--------------------------------------------------------------
# Claim Certificate Policy (for Fleet Provisioning by Claim)
#--------------------------------------------------------------
resource "aws_iot_policy" "claim_policy" {
  name = "${var.project_name}-claim-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["iot:Connect"]
        Resource = [
          "arn:aws:iot:${var.aws_region}:*:client/claim-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iot:Publish",
          "iot:Receive"
        ]
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
          "arn:aws:iot:${var.aws_region}:*:topicfilter/$aws/provisioning-templates/${var.project_name}-prov-template/provision/*"
        ]
      }
    ]
  })
}