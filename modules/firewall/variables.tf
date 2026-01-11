# -------------------------------------------------------------
# Existing Variables
# -------------------------------------------------------------
variable "firewall_name" {
  description = "Name of the firewall"
  type        = string
}

variable "firewall_policy_name" {
  description = "Name of the firewall policy"
  type        = string
}

variable "firewall_policy_arn" {
  description = "ARN of the Network Firewall Policy created in the dedicated policy module."
  type        = string
}

variable "transit_gateway_id" {
  type        = string
  description = "The ID of the Transit Gateway"
}

variable "availability_zone_ids" {
  type        = list(string)
  description = "List of physical AZ IDs (e.g., use1-az1, use1-az2)"
  
  validation {
    condition     = length([for id in var.availability_zone_ids : id if can(regex("^[a-z]{2,3}[0-9]-az[0-9]$", id))]) == length(var.availability_zone_ids)
    error_message = "All AZs must be provided as physical AZ IDs ('use1-az1') not az names ('us-east-1a')."
  }
}

variable "tags" {
  description = "Tags to apply to the VPC"
  type        = map(string)
  default     = {}
}

variable "application" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "base_tags" { type = map(string) }
variable "env" { type = string }