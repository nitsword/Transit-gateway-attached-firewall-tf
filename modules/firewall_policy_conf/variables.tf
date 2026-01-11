variable "firewall_policy_name" {
  description = "Name for the AWS Network Firewall policy."
  type        = string
}

# variable "environment" {
#   description = "Deployment environment (e.g., dev, prod)."
#   type        = string
# }

# -------------------------------------------------------------------------
# 5-Tuple Stateful Rule Group Inputs
# -------------------------------------------------------------------------
variable "five_tuple_rg_capacity" {
  description = "Capacity for the 5-tuple stateful rule group."
  type        = number
}

variable "five_tuple_rules" {
  description = "List of 5-tuple stateful rules as objects."
  type = list(object({
    action = string
    protocol = string
    source = string
    source_port = string
    destination = string
    destination_port = string
    direction = string
    sid = string
  }))
}

# -------------------------------------------------------------------------
# Domain Rule Groups (FQDN-based)
# -------------------------------------------------------------------------
variable "domain_rg_capacity" {
  description = "Capacity for domain-based rule groups (allowlist/denylist)."
  type        = number
}

variable "stateful_rule_group_arns" {
  description = "List of additional stateful rule group ARNs to attach."
  type        = list(string)
  default     = []
}

variable "stateful_rule_order" {
  description = "Stateful rule evaluation order for AWS Network Firewall."
  type        = string
  default     = "STRICT_ORDER"
}

variable "stateful_rule_group_objects" {
  description = "List of objects with ARN and priority"
  type = list(object({ arn = string, priority = number }))
  default = []
}

variable "priority_domain_allowlist" {
  description = "Priority for the internal Domain ALLOWLIST rule group (used in STRICT_ORDER)."
  type        = number
}

variable "priority_five_tuple" {
  description = "Priority for the internal 5-Tuple rule group (used in STRICT_ORDER)."
  type        = number
}

variable "tags" {
  description = "Tags to apply to the VPC"
  type        = map(string)
  default     = {}
}

variable "domain_list" {
  type        = list(string)
  description = "List of domains to allow (e.g., ['.google.com'])"
  default     = []
}

variable "enable_domain_allowlist" {
  description = "Toggle to enable or disable the domain allowlist rule group"
  type        = bool
  default     = false
}

variable "application" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "base_tags" { type = map(string) }
variable "env" { type = string }