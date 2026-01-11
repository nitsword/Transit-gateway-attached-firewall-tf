output "firewall_arn" {
  description = "The ARN of the AWS Network Firewall resource."
  value       = aws_networkfirewall_firewall.inspection_firewall.arn
}

output "firewall_id" {
  description = "The ID of the AWS Network Firewall resource."
  value       = aws_networkfirewall_firewall.inspection_firewall.id
}

output "firewall_sync_states" {
  description = "The sync states of the firewall containing AZ and Endpoint IDs"
  value       = aws_networkfirewall_firewall.inspection_firewall.firewall_status[0].sync_states
}

output "firewall_status" {
  description = "The status of the firewall, including the VPC endpoint IDs"
  value = aws_networkfirewall_firewall.inspection_firewall.firewall_status
}

output "tgw_attachment_id" {
  description = "The Attachment ID created for the TGW."
  value = aws_networkfirewall_firewall.inspection_firewall.firewall_status[0].transit_gateway_attachment_sync_states[0].attachment_id
}