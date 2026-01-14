variable "firewall_policy_name" {
  description = "Name for the AWS Network Firewall policy."
  type        = string
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
  default     = true
}

variable "domain_group_arn" {
  type        = string
  description = "The ARN of the domain list rule group"
  default     = null
}

variable "five_tuple_group_arn" {
  type        = string
  description = "The ARN of the 5-tuple rule group"
}

variable "suricata_group_arn" {
  type        = string
  description = "The ARN of the Suricata rule group"
}
variable "priority_suricata" {
  description = "Priority for the Suricata rule group (used in STRICT_ORDER)."
  type        = number
}

variable "application" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "base_tags" { type = map(string) }
variable "env" { type = string }