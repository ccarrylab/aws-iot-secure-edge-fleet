
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

resource "aws_s3_bucket_notification" "ota_notification" {
  bucket = aws_s3_bucket.ota_packages.id

  topic {
    topic_arn     = aws_sns_topic.fleet_alerts.arn
    events        = ["s3:ObjectCreated:*"]
  }
}
