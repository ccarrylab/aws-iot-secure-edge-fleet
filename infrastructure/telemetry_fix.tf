resource "aws_iot_topic_rule" "telemetry_route" {
  name        = "secure_edge_fleet_telemetry_route"
  description = "Route device telemetry to CloudWatch Logs"
  enabled     = true

  sql = "SELECT * FROM 'secure-edge-fleet/telemetry/+'"
  sql_version = "2016-03-23"

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.iot_core.name
    role_arn       = aws_iam_role.iot_logging.arn
  }
}
