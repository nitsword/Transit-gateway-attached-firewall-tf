resource "aws_networkfirewall_firewall_policy" "firewall_policy" {
  name = var.firewall_policy_name

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:drop"]
    stateful_default_actions           = ["aws:drop_established", "aws:alert_established"]

    stateful_engine_options {
      rule_order = var.stateful_rule_order
    }

    #  Reference Suricata Rule Group
    dynamic "stateful_rule_group_reference" {
      for_each = var.suricata_group_arn != null ? [var.suricata_group_arn] : []
      content {
        resource_arn = stateful_rule_group_reference.value
        priority     = var.stateful_rule_order == "STRICT_ORDER" ? var.priority_suricata : null
      }
    }

    # Reference Domain Group
    dynamic "stateful_rule_group_reference" {
      for_each = var.domain_group_arn != null ? [var.domain_group_arn] : []
      content {
        resource_arn = stateful_rule_group_reference.value
        priority     = var.stateful_rule_order == "STRICT_ORDER" ? var.priority_domain_allowlist : null
      }
    }

    # Reference 5-Tuple Group
    stateful_rule_group_reference {
      resource_arn = var.five_tuple_group_arn
      priority     = var.stateful_rule_order == "STRICT_ORDER" ? var.priority_five_tuple : null
    }
  }

  tags = merge({
    Name            = "${var.application}-${var.environment}-firewall-policy-${var.region}"
    "Resource Type" = "firewall-policy"
    "Creation Date" = timestamp()
    "Environment"   = var.environment
    "Application"   = var.application
    "Created by"    = "Cloud Network Team"
    "Region"        = var.region
  }, var.base_tags)
}