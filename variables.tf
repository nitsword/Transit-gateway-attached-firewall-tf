variable "region" {
  description = "AWS region"
  type        = string
}

variable "azs" {
  description = "List of availability zones"
  type        = list(string)
  default     = []
}

variable "bucket_name" {
  description = "Name of the s3 bucket"
  type        = string
  default     = ""
}

variable "firewall_name" {
  description = "Name of the firewall"
  type        = string
  default     = "inspection-firewall"
}

variable "firewall_policy_name" {
  description = "Name of the firewall policy"
  type        = string
  default     = "inspection-firewall-policy"
}

variable "priority_domain_allowlist" {
  description = "Priority for the Domain ALLOWLIST rule group (STRICT_ORDER evaluation)."
  type        = number
}

variable "priority_five_tuple" {
  description = "Priority for the 5-Tuple rule group (STRICT_ORDER evaluation)."
  type        = number
}

variable "stateful_rule_group_arns" {
  description = "List of ARNs for stateful rule groups"
  type        = list(string)
  default     = []
}

variable "five_tuple_rg_capacity" {
  description = "Capacity for the 5-Tuple rule group."
  type        = number
}


variable "domain_rg_capacity" {
  description = "Capacity for the Domain rule group."
  type        = number
}

variable "allowed_domains_list" {
  description = "FQDNs/domains for targets in the Domain List rule group."
  type        = list(string)
  default     = []
}

variable "enable_domain_allowlist" {
  type    = bool
  default = false
}

variable "tags" {
  type        = map(string)
  description = "Tags to apply to resources"
  default     = {}
}

variable "application" { type = string }
variable "environment" { type = string }
variable "env" { type = string }

variable "base_tags" {
  type    = map(string)
  default = { "Created by" = "Cloud Network Team" }
}

variable "stateful_rule_order" {
  description = "Stateful rule evaluation order for Network Firewall: 'STRICT_ORDER' or 'DEFAULT_ORDER'."
  type        = string
  default     = "STRICT_ORDER"
  validation {
    condition     = contains(["STRICT_ORDER", "DEFAULT_ORDER"], var.stateful_rule_order)
    error_message = "stateful_rule_order must be either STRICT_ORDER or DEFAULT_ORDER"
  }
}

variable "stateful_rule_group_objects" {
  description = "List of objects with ARN and priority for external stateful rule groups"
  type        = list(object({ arn = string, priority = number }))
  default     = []
}

variable "transit_gateway_id" {
  description = "Transit Gateway ID"
  type        = string
}

variable "availability_zone_ids" {
  type        = list(string)
  description = "List of physical AZ IDs (e.g., use1-az1, use1-az2)"
}

variable "rule_set_name" {
  description = "The specific firewall/region folder name"
  type        = string
  # Example: rules-fw1-us-east1
}

variable "suricata_rg_capacity" {
  description = "Capacity for the suricata stateful rule group."
  type        = number
}

variable "priority_suricata" {
  type        = number
  description = "The priority for the Suricata rule group (e.g., 10)"
}

variable "suricata_group_arn" {
  type    = string
  default = null
}
