output "thing_group_name" {
  description = "Name of the IoT Thing Group"
  value       = aws_iot_thing_group.edge_fleet.name
}

output "device_policy_name" {
  description = "Name of the IoT device policy"
  value       = aws_iot_policy.device_policy.name
}

output "ota_bucket_name" {
  description = "S3 bucket for OTA packages"
  value       = aws_s3_bucket.ota_packages.bucket
}

output "aws_region" {
  value = var.aws_region
}

output "provisioning_template_name" {
  description = "Fleet Provisioning template name"
  value       = aws_iot_provisioning_template.edge_fleet.name
}

output "fleet_provisioning_role_arn" {
  description = "IAM role used by Fleet Provisioning"
  value       = aws_iam_role.fleet_provisioning.arn
}

output "claim_policy_name" {
  description = "IoT policy for claim certificates"
  value       = aws_iot_policy.claim_policy.name
}