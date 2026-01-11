output "firewall_id" {
  description = "The ID of the Network Firewall"
  value       = module.firewall.firewall_id
}

output "firewall_arn" {
  description = "The ARN of the Network Firewall (needed for logging/policy updates)"
  value       = module.firewall.firewall_arn
}

output "firewall_endpoint_map" {
  description = "Map of AZ to Firewall Endpoint ID"
  value = {
    for state in module.firewall.firewall_status[0].sync_states :
    state.availability_zone => state.attachment[0].endpoint_id
  }
}

output "firewall_policy_arn" {
  description = "The ARN of the Firewall Policy."
  value       = module.firewall_policy_conf.firewall_policy_arn
}

output "logging_bucket_name" {
  description = "The name of the S3 bucket where logs are stored."
  value       = module.secure_s3_bucket.bucket_id
}

output "domain_rule_group_arn" {
  description = "ARN of the domain list rule group."
  value       = module.domain_rules.rule_group_arn
}

output "five_tuple_rule_group_arn" {
  description = "ARN of the 5-tuple rule group."
  value       = module.five_tuple_rules.rule_group_arn
}

