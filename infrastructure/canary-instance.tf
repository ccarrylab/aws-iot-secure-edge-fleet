# ---------------------------------------------------------------------------
# canary-instance.tf  —  one throwaway EC2 instance to run the canary on
#
# WHY THIS IS SEPARATE AND OFF BY DEFAULT
#
# The rollback path can only be verified on a Linux box with systemd, a real
# filesystem, and a certificate. A laptop cannot do it: macOS has no systemd,
# and the things under test — the ExecStartPre guard, the symlink swap, the
# chmod +x on the guard — are all abstractions inside a container.
#
# This is NOT part of the fleet. It joins no Thing Group, gets no IoT
# certificate from here, and is not something you leave running. It is an
# instance you start, boot the agent on, break deliberately, and destroy.
#
# enable_canary defaults to false. Nothing here is created until you ask:
#
#   terraform apply -var="enable_canary=true" -var="canary_key_name=edge-canary"
#
# canary_ssh_cidr defaults to the operator's own address; update it there when
# your ISP hands you a new one. And when you are done:
#
#   terraform destroy -var="enable_canary=true"
#
# Cost: a t3.micro is free-tier eligible for 12 months on a new account and
# pennies per hour otherwise. The Elastic IP is the only charge that persists,
# and only while it is unattached to a running instance.
# ---------------------------------------------------------------------------

variable "enable_canary" {
  description = <<-EOT
    Create a single throwaway EC2 instance for canary testing. Off by default:
    this is a test rig, not fleet infrastructure.
  EOT
  type        = bool
  default     = false
}

variable "canary_ssh_cidr" {
  description = <<-EOT
    CIDR allowed to SSH to the canary instance. Nothing else can reach it — the
    agent only makes outbound connections to IoT Core, so there is no reason to
    open 8883 or anything else inbound.

    Set this to your own public address. Residential addresses change when the
    router reconnects, so if SSH stops working mid-test, update this and re-apply.

    Defaults to a TEST-NET-3 documentation range so a forgotten value fails
    closed (nobody can reach it) rather than open.
  EOT
  type        = string
  default     = "173.49.87.129/32"

  validation {
    condition     = can(cidrnetmask(var.canary_ssh_cidr))
    error_message = "canary_ssh_cidr must be a valid CIDR, e.g. 203.0.113.7/32."
  }
}

variable "canary_key_name" {
  description = <<-EOT
    Name of an existing EC2 key pair for SSH. Create one first if you have not:
      aws ec2 create-key-pair --key-name edge-canary \
        --query KeyMaterial --output text > edge-canary.pem
      chmod 600 edge-canary.pem
  EOT
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_canary || length(var.canary_key_name) > 0
    error_message = "canary_key_name is required when enable_canary is true."
  }
}

variable "canary_instance_type" {
  description = "Instance size. t3.micro is plenty: the agent is one Python process."
  type        = string
  default     = "t3.micro"
}

locals {
  canary_name = "${var.project_name}-canary"
}

# The IoT data endpoint, so the instance needs no AWS credentials at all — no
# CLI, no instance profile, nothing on disk to leak. Feed this into the unit env.
data "aws_iot_endpoint" "canary" {
  count         = var.enable_canary ? 1 : 0
  endpoint_type = "iot:Data-ATS"
}

# Ubuntu 24.04 LTS: systemd, Python 3.12, and an apt that still has support.
# Resolved at plan time rather than pinned to an AMI id that goes stale in
# every region.
data "aws_ami" "canary" {
  count       = var.enable_canary ? 1 : 0
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "canary" {
  count       = var.enable_canary ? 1 : 0
  name        = "${local.canary_name}-ssh"
  description = "SSH from one address only. The agent needs no inbound ports."

  ingress {
    description = "SSH from the operator address"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.canary_ssh_cidr]
  }

  egress {
    description = "All outbound: IoT Core on 8883, HTTPS for S3, apt for packages"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = local.canary_name }
}

resource "aws_instance" "canary" {
  count = var.enable_canary ? 1 : 0

  #checkov:skip=CKV2_AWS_41:No instance profile on purpose - the agent authenticates with its X.509 certificate, not an instance role
  ami                    = data.aws_ami.canary[0].id
  instance_type          = var.canary_instance_type
  key_name               = var.canary_key_name
  vpc_security_group_ids = [aws_security_group.canary[0].id]

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true

    # The rollback test deletes and recreates releases under this volume, and a
    # failed rollback is meant to be observable rather than fatal. Keep the
    # volume if the instance is terminated and you can detach and inspect it.
    delete_on_termination = false
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only
    http_endpoint = "enabled"
  }

  tags = {
    Name        = local.canary_name
    Purpose     = "canary-testing"
    Environment = var.environment
  }

  lifecycle {
    # A canary is meant to be broken and rebuilt. Do not let a refreshed AMI
    # confuse a plan into replacing the instance mid-test.
    ignore_changes = [ami]
  }
}

# A stable address across stop/start, so the SSH target does not change when you
# stop the instance between test runs.
resource "aws_eip" "canary" {
  count  = var.enable_canary ? 1 : 0
  domain = "vpc"

  instance = aws_instance.canary[0].id

  tags = { Name = local.canary_name }
}

output "canary_public_ip" {
  description = "SSH target"
  value       = var.enable_canary ? aws_eip.canary[0].public_ip : null
}

output "canary_ssh_command" {
  description = "Ready-made SSH command"
  value       = var.enable_canary ? "ssh -i ${var.canary_key_name}.pem ubuntu@${aws_eip.canary[0].public_ip}" : null
}

output "canary_iot_endpoint" {
  description = "Value for IOT_ENDPOINT on the canary. Read it here rather than running the CLI on the box."
  value       = var.enable_canary ? data.aws_iot_endpoint.canary[0].endpoint_address : null
}

output "canary_scope_down_command" {
  description = "Run this when the tests are done. There is nothing here worth leaving up."
  value       = "terraform destroy -var=\"enable_canary=true\""
}
