output "firewall_policy_arn" {
  description = "The ARN of the fw Policy to be attached to the FW Resource."
  value       = aws_networkfirewall_firewall_policy.firewall_policy.arn
}