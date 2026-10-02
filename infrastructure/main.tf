1|# --------------------------------------------------------------
2|# Global Identity and Locals
3|# --------------------------------------------------------------
4|data "aws_caller_identity" "current" {}
5|
6|locals {
7|  account_id = data.aws_caller_identity.current.account_id
8|  iot_arn    = "arn:aws:iot:${var.aws_region}:${local.account_id}"
9|}
10|
11|# --------------------------------------------------------------
12|# Basic IoT Core resources
13|# --------------------------------------------------------------
14|
15|resource "aws_iot_thing_group" "edge_fleet" {
16|  name = "${var.project_name}-fleet"
17|
18|  properties {
19|    attribute_payload {
20|      attributes = {
21|        environment = var.environment
22|        type        = "edge-device"
23|      }
24|    }
25|  }
26|}
27|
28|# --------------------------------------------------------------
29|# Device Security
30|# --------------------------------------------------------------
31|
32|resource "aws_iot_policy" "device_policy" {
33|  name = "${var.project_name}-device-policy"
34|
35|  policy = jsonencode({
36|    Version = "2012-10-17"
37|    Statement = [
38|      {
39|        Sid      = "ConnectAsOwnThingOnly"
40|        Effect   = "Allow"
41|        Action   = ["iot:Connect"]
42|        Resource = ["${local.iot_arn}:client/$${iot:Connection.Thing.ThingName}"]
43|      },
44|      {
45|        Sid    = "OwnTelemetryAndJobsOnly"
46|        Effect = "Allow"
47|        Action = ["iot:Publish", "iot:Receive"]
48|        Resource = [
49|          "${local.iot_arn}:topic/${var.project_name}/telemetry/$${iot:Connection.Thing.ThingName}",
50|          "${local.iot_arn}:topic/$aws/things/$${iot:Connection.Thing.ThingName}/jobs/*"
51|        ]
52|      },
53|      {
54|        Sid      = "SubscribeToOwnJobsOnly"
55|        Effect   = "Allow"
56|        Action   = ["iot:Subscribe"]
57|        Resource = ["${local.iot_arn}:topicfilter/$aws/things/$${iot:Connection.Thing.ThingName}/jobs/*"]
58|      },
59|      {
60|        Sid    = "OwnJobExecutionsOnly"
61|        Effect = "Allow"
62|        Action = [
63|          "iot:DescribeJobExecution",
64|          "iot:GetPendingJobExecutions",
65|          "iot:StartNextPendingJobExecution",
66|          "iot:UpdateJobExecution"
67|        ]
68|        Resource = ["${local.iot_arn}:thing/$${iot:Connection.Thing.ThingName}"]
69|      },
70|      {
71|        Sid      = "AssumeOtaReadRole"
72|        Effect   = "Allow"
73|        Action   = ["iot:AssumeRoleWithCertificate"]
74|        Resource = ["${local.iot_arn}:rolealias/${var.project_name}-device-ota-read"]
75|      }
76|    ]
77|  })
78|}
79|
80|# --------------------------------------------------------------
81|# Fleet Provisioning
82|# --------------------------------------------------------------
83|
84|resource "aws_iam_role" "fleet_provisioning" {
85|  name = "${var.project_name}-fleet-provisioning-role"
86|
87|  assume_role_policy = jsonencode({
88|    Version = "2012-10-17"
89|    Statement = [{
90|      Effect    = "Allow"
91|      Principal = { Service = "iot.amazonaws.com" }
92|      Action    = "sts:AssumeRole"
93|    }]
94|  })
95|}
96|
97|resource "aws_iam_role_policy" "fleet_provisioning" {
98|  name = "${var.project_name}-fleet-provisioning-policy"
99|  role = aws_iam_role.fleet_provisioning.id
100|
101|  policy = jsonencode({
102|    Version = "2012-10-17"
103|    Statement = [
104|      {
105|        Sid    = "ManageOnlyOurThingNamespace"
106|        Effect = "Allow"
107|        Action = [
108|          "iot:CreateThing", "iot:DescribeThing", "iot:UpdateThing",
109|          "iot:AddThingToThingGroup", "iot:RemoveThingFromThingGroup",
110|          "iot:ListThingGroupsForThing", "iot:ListPrincipalThings",
111|          "iot:AttachThingPrincipal", "iot:DetachThingPrincipal"
112|        ]
113|        Resource = ["${local.iot_arn}:thing/${var.project_name}-*"]
114|      },
115|      {
116|        Sid      = "ManageCertificates"
117|        Effect   = "Allow"
118|        Action   = ["iot:RegisterCertificate", "iot:DescribeCertificate", "iot:UpdateCertificate"]
119|        Resource = ["${local.iot_arn}:cert/*"]
120|      },
121|      {
122|        Sid      = "AttachTheDevicePolicyOnly"
123|        Effect   = "Allow"
124|        Action   = ["iot:AttachPolicy", "iot:ListAttachedPolicies"]
125|        Resource = ["${local.iot_arn}:policy/${var.project_name}-device-policy"]
126|      },
127|      {
128|        Sid      = "ReadTheFleetGroup"
129|        Effect   = "Allow"
130|        Action   = ["iot:DescribeThingGroup", "iot:ListThingGroups"]
131|        Resource = ["${local.iot_arn}:thinggroup/${var.project_name}-fleet"]
132|      },
133|      {
134|        Sid      = "RegisterAgainstTheTemplate"
135|        Effect   = "Allow"
136|        Action   = ["iot:RegisterThing"]
137|        Resource = ["${local.iot_arn}:provisioningtemplate/${var.project_name}-prov-template"]
138|      }
139|    ]
140|  })
141|}
142|
143|resource "aws_iot_provisioning_template" "edge_fleet" {
144|  name                  = "${var.project_name}-prov-template"
145|  description           = "Provisioning template for secure edge fleet devices"
146|  enabled               = true
147|  provisioning_role_arn = aws_iam_role.fleet_provisioning.arn
148|
149|  template_body = jsonencode({
150|    Parameters = { SerialNumber = { Type = "String" } }
151|    Resources = {
152|      thing = {
153|        Type = "AWS::IoT::Thing"
154|        Properties = {
155|          ThingName = { "Fn::Join" = ["", ["${var.project_name}-", { "Ref" = "SerialNumber" }]] }
156|          AttributePayload = {
157|            serialNumber = { "Ref" = "SerialNumber" }
158|            environment  = var.environment
159|          }
160|          ThingGroups = [aws_iot_thing_group.edge_fleet.name]
161|        }
162|      }
163|      certificate = {
164|        Type = "AWS::IoT::Certificate"
165|        Properties = {
166|          CertificateId = { "Ref" = "AWS::IoT::Certificate::Id" }
167|          Status        = "Active"
168|        }
169|      }
170|      policy = {
171|        Type       = "AWS::IoT::Policy"
172|        Properties = { PolicyName = aws_iot_policy.device_policy.name }
173|      }
174|    }
175|  })
176|}
177|
178|resource "aws_iot_policy" "claim_policy" {
179|  name = "${var.project_name}-claim-policy"
180|  policy = jsonencode({
181|    Version = "2012-10-17"
182|    Statement = [
183|      {
184|        Effect   = "Allow"
185|        Action   = ["iot:Connect"]
186|        Resource = ["arn:aws:iot:${var.aws_region}:*:client/claim-*"]
187|      },
188|      {
189|        Effect = "Allow"
190|        Action = ["iot:Publish", "iot:Receive"]
191|        Resource = [
192|          "arn:aws:iot:${var.aws_region}:*:topic/$aws/certificates/create/*",
193|          "arn:aws:iot:${var.aws_region}:*:topic/$aws/provisioning-templates/${var.project_name}-prov-template/provision/*"
194|        ]
195|      },
196|      {
197|        Effect = "Allow"
198|        Action = ["iot:Subscribe"]
199|        Resource = [
200|          "arn:aws:iot:${var.aws_region}:*:topicfilter/$aws/certificates/create/*",
201|          "arn:aws:iot:${var.aws_region}:*:topicfilter/$aws/provisioning-templates/${var.project_name}-prov-template/provision/*"
202|        ]
203|      }
204|    ]
205|  })
206|}
207|
208|# --------------------------------------------------------------
209|# OTA Supply Chain
210|# --------------------------------------------------------------
211|
254|
255|resource "aws_kms_key" "ota" {
256|  description             = "Encryption for ${var.project_name} OTA packages"
257|  deletion_window_in_days = 30
258|  enable_key_rotation     = true
259|
260|}
261|
262|resource "aws_kms_alias" "ota" {
263|  name          = "alias/${var.project_name}-ota"
264|  target_key_id = aws_kms_key.ota.key_id
265|}
266|
267|resource "aws_s3_bucket" "ota_packages" {
268|  bucket        = "${var.project_name}-ota-packages-${var.environment}"
269|  force_destroy = var.environment == "dev"
270|}
271|
272|resource "aws_s3_bucket_versioning" "ota_packages" {
273|  bucket = aws_s3_bucket.ota_packages.id
274|  versioning_configuration { status = "Enabled" }
275|}
276|
277|resource "aws_s3_bucket_public_access_block" "ota_packages" {
278|  bucket                  = aws_s3_bucket.ota_packages.id
279|  block_public_acls       = true
280|  block_public_policy     = true
281|  ignore_public_acls      = true
282|  restrict_public_buckets = true
283|}
284|
285|resource "aws_s3_bucket_server_side_encryption_configuration" "ota_packages" {
286|  bucket = aws_s3_bucket.ota_packages.id
287|  rule {
288|    apply_server_side_encryption_by_default {
289|      sse_algorithm     = "aws:kms"
290|      kms_master_key_id = aws_kms_key.ota.arn
291|    }
292|    bucket_key_enabled = true
293|  }
294|}
295|
296|resource "aws_s3_bucket_ownership_controls" "ota_packages" {
297|  bucket = aws_s3_bucket.ota_packages.id
298|  rule { object_ownership = "BucketOwnerPreferred" }
299|}
300|
301|resource "aws_s3_bucket_policy" "ota_packages" {
302|  bucket = aws_s3_bucket.ota_packages.id
303|  policy = jsonencode({
304|    Version = "2012-10-17"
305|    Statement = [{
306|      Sid       = "DenyNonTLS"
307|      Effect    = "Deny"
308|      Principal = "*"
309|      Action    = "s3:*"
310|      Resource  = [aws_s3_bucket.ota_packages.arn, "${aws_s3_bucket.ota_packages.arn}/*"]
311|      Condition = { Bool = { "aws:SecureTransport" = "false" } }
312|    }]
313|  })
314|}
315|
316|resource "aws_s3_bucket_lifecycle_configuration" "ota_packages" {
317|  bucket = aws_s3_bucket.ota_packages.id
318|  rule {
319|    id     = "expire-old-releases"
320|    status = "Enabled"
321|    filter {}
322|    noncurrent_version_expiration { noncurrent_days = 90 }
323|    abort_incomplete_multipart_upload { days_after_initiation = 7 }
324|  }
325|}
326|
327|resource "aws_iam_policy" "ota_publisher" {
328|  name        = "${var.project_name}-ota-publisher"
329|  description = "Write OTA releases only. Attach to the CI role, never to a human."
330|  policy = jsonencode({
331|    Version = "2012-10-17"
332|    Statement = [
333|      {
334|        Sid      = "PublishReleases"
335|        Effect   = "Allow"
336|        Action   = ["s3:PutObject", "s3:AbortMultipartUpload"]
337|        Resource = ["${aws_s3_bucket.ota_packages.arn}/packages/*"]
338|      },
339|      {
340|        Sid      = "PublishSignatures"
341|        Effect   = "Allow"
342|        Action   = ["s3:PutObject"]
343|        Resource = ["${aws_s3_bucket.ota_packages.arn}/signatures/*"]
344|      },
345|      {
346|        Sid       = "EncryptWithOurKey"
347|        Effect    = "Allow"
348|        Action    = ["kms:GenerateDataKey", "kms:DescribeKey"]
349|        resources = ["*"]
350|      }
351|    ]
352|  })
353|}
354|
355|# --------------------------------------------------------------
356|# Observability (Logging & Telemetry)
357|# --------------------------------------------------------------
358|
359|resource "aws_cloudwatch_log_group" "iot_core" {
360|  name              = "/aws/iot/${var.project_name}-core"
361|  retention_in_days = 365
362|  kms_key_id        = aws_kms_key.ota.arn
363|}
364|
365|resource "aws_iam_role" "iot_logging" {
366|  name = "${var.project_name}-iot-logging-role"
367|  assume_role_policy = jsonencode({
368|    Version = "2012-10-17"
369|    Statement = [{
370|      Effect    = "Allow"
371|      Principal = { Service = "iot.amazonaws.com" }
372|      Action    = "sts:AssumeRole"
373|    }]
374|  })
375|}
376|
377|resource "aws_iam_role_policy" "iot_logging" {
378|  name = "${var.project_name}-iot-logging-policy"
379|  role = aws_iam_role.iot_logging.id
380|  policy = jsonencode({
381|    Version = "2012-10-17"
382|    Statement = [{
383|      Effect   = "Allow"
384|      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
385|      Resource = ["${aws_cloudwatch_log_group.iot_core.arn}:*"]
386|    }]
387|  })
388|}
389|
390|resource "aws_iot_logging_options" "core" {
391|  role_arn          = aws_iam_role.iot_logging.arn
392|  default_log_level = "INFO"
393|}
394|
395|resource "aws_iot_topic_rule" "telemetry_route" {
396|  name        = "secure_edge_fleet_telemetry_route"
397|  description = "Route device telemetry to CloudWatch Logs"
398|  enabled     = true
399|  sql         = "SELECT * FROM 'secure-edge-fleet/telemetry/+'"
400|  sql_version = "2016-03-23"
401|
402|  cloudwatch_logs {
403|    log_group_name = aws_cloudwatch_log_group.iot_core.name
404|    role_arn       = aws_iam_role.iot_logging.arn
405|  }
406|}
407|
408|# --------------------------------------------------------------
409|# Monitoring (Dead Man's Switch)
410|# --------------------------------------------------------------
411|
412|resource "aws_sns_topic" "fleet_alerts" {
413|  name              = "${var.project_name}-fleet-alerts"
414|  kms_master_key_id = aws_kms_key.ota.id
415|}
416|
417|resource "aws_sns_topic_policy" "fleet_alerts_policy" {
418|  arn = aws_sns_topic.fleet_alerts.arn
419|
420|  policy = jsonencode({
421|    Version = "2012-10-17"
422|    Statement = [
423|      {
424|        Effect    = "Allow"
425|        Principal = { Service = "s3.amazonaws.com" }
426|        Action    = "sns:Publish"
427|        Resource  = [aws_sns_topic.fleet_alerts.arn]
428|        Condition = {
429|          ArnLike = { "aws:SourceArn" = aws_s3_bucket.ota_packages.arn }
430|        }
431|      }
432|    ]
433|  })
434|}
435|
436|resource "aws_cloudwatch_log_metric_filter" "telemetry_heartbeat" {
437|  name           = "TelemetryHeartbeat"
438|  pattern        = "{ $.status = \"online\" }"
439|  log_group_name = aws_cloudwatch_log_group.iot_core.name
440|
441|  metric_transformation {
442|    name      = "HeartbeatCount"
443|    namespace = "SecureEdgeFleet"
444|    value     = "1"
445|  }
446|}
447|
448|resource "aws_cloudwatch_metric_alarm" "device_offline" {
449|  alarm_name          = "${var.project_name}-device-offline"
450|  comparison_operator = "LessThanThreshold"
451|  evaluation_periods  = "3"
452|  metric_name         = "HeartbeatCount"
453|  namespace           = "SecureEdgeFleet"
454|  period              = "300"
455|  statistic           = "Sum"
456|  threshold           = "1"
457|  alarm_actions       = [aws_sns_topic.fleet_alerts.arn]
458|}
459|
460|resource "aws_s3_bucket" "log_bucket" {
461|  bucket = "${var.project_name}-logs-${var.environment}"
462|}
463|
464|resource "aws_s3_bucket_ownership_controls" "log_bucket_oc" {
465|  bucket = aws_s3_bucket.log_bucket.id
466|  rule { object_ownership = "BucketOwnerPreferred" }
467|}
468|
469|resource "aws_s3_bucket_acl" "log_bucket_acl" {
470|  bucket = aws_s3_bucket.log_bucket.id
471|  acl    = "log-delivery-write"
472|}
473|
474|resource "aws_s3_bucket_logging" "ota_logging" {
475|  bucket        = aws_s3_bucket.ota_packages.id
476|  target_bucket = aws_s3_bucket.log_bucket.id
477|  target_prefix = "log/"
478|}
479|
480|resource "aws_s3_bucket_notification" "ota_notification" {
481|  bucket = aws_s3_bucket.ota_packages.id
482|  topic {
483|    topic_arn = aws_sns_topic.fleet_alerts.arn
484|    events    = ["s3:ObjectCreated:*"]
485|  }
486|}