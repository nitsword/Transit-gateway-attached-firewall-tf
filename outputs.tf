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


