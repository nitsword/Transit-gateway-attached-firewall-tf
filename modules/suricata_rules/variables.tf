variable "firewall_policy_name" {
  description = "Name for the AWS Network Firewall policy."
  type        = string
}

variable "suricata_rg_capacity" {
  description = "Capacity for the suricata stateful rule group."
  type        = number
}

variable "home_net_cidrs" {
  description = "CIDR blocks for the home network."
  type        = list(string)
}

variable "tags" {
  description = "Tags to apply to the VPC"
  type        = map(string)
  default     = {}
}

variable "rules_string" {
  description = "The concatenated Suricata rules string."
  type        = string
}

variable "application" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "base_tags" { type = map(string) }
variable "env" { type = string }