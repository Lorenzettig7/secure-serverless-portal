variable "project_prefix" { type = string }
variable "region"         { type = string }
variable "domain_name"    { type = string }  # "portal.secureschoolcloud.org"
variable "hosted_zone_id" { type = string }  # Zxxxxxxxx from Route53 for secureschoolcloud.org
variable "common_tags"    { type = map(string) }
