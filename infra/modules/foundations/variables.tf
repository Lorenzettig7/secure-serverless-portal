variable "project_prefix" { type = string }
variable "region" { type = string }
variable "common_tags" { type = map(string) }
variable "alert_emails" {
  type        = list(string)
  description = "Emails to subscribe to security alerts"
  default     = [] # empty by default
}