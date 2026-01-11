output "rule_group_arn" {
  value = length(aws_networkfirewall_rule_group.domain_allowlist) > 0 ? aws_networkfirewall_rule_group.domain_allowlist[0].arn : null
}