resource "aws_sns_topic" "security_alerts" {
  name = "portal-security-alerts"
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  for_each = toset(var.alert_emails)
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# 1) Root account usage
resource "aws_cloudwatch_event_rule" "root_usage" {
  name        = "portal-root-usage"
  description = "Alert on root account usage"
  event_pattern = jsonencode({
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "userIdentity": {
        "type": ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_usage_to_sns" {
  rule      = aws_cloudwatch_event_rule.root_usage.name
  target_id = "sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# 2) Attempts to Stop CloudTrail logging
resource "aws_cloudwatch_event_rule" "trail_stop" {
  name        = "portal-cloudtrail-stop"
  description = "Alert when someone tries to StopLogging on CloudTrail"
  event_pattern = jsonencode({
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["cloudtrail.amazonaws.com"],
      "eventName":   ["StopLogging"]
    }
  })
}

resource "aws_cloudwatch_event_target" "trail_stop_to_sns" {
  rule      = aws_cloudwatch_event_rule.trail_stop.name
  target_id = "sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# 3) IAM changes involving portal-* roles/policies
resource "aws_cloudwatch_event_rule" "iam_portal_changes" {
  name        = "portal-iam-changes"
  description = "Alert on IAM changes for portal-* roles/policies"
  event_pattern = jsonencode({
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["iam.amazonaws.com"],
      "requestParameters": {
        # Broadly match names that start with portal-
        "roleName":   [{ "prefix": "portal-" }],
        "policyName": [{ "prefix": "portal-" }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_portal_changes_to_sns" {
  rule      = aws_cloudwatch_event_rule.iam_portal_changes.name
  target_id = "sns"
  arn       = aws_sns_topic.security_alerts.arn
}

# Allow EventBridge to publish to SNS
resource "aws_sns_topic_policy" "security_alerts_policy" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowEventBridgePublish",
      Effect    = "Allow",
      Principal = { Service = "events.amazonaws.com" },
      Action    = "SNS:Publish",
      Resource  = aws_sns_topic.security_alerts.arn
    }]
  })
}
