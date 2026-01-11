locals {
  # This stays to handle the ARN list for the policy references
  allowlist_arn_list = aws_networkfirewall_rule_group.domain_allowlist[*].arn
}

// -------------------------------------------------------------------------
// Stateful Rule Group: 5-Tuple
// -------------------------------------------------------------------------
resource "aws_networkfirewall_rule_group" "five_tuple_rule_group" {
  name        = "five-tuple-rg-${var.firewall_policy_name}"
  description = "Standard 5-tuple rule group using standard stateful rules."
  type        = "STATEFUL"
  capacity    = var.five_tuple_rg_capacity

  rule_group {
    stateful_rule_options {
      rule_order = var.stateful_rule_order
    }

    rules_source {
      dynamic "stateful_rule" {
        for_each = var.five_tuple_rules
        content {
          action = upper(stateful_rule.value.action)
          header {
            protocol         = upper(stateful_rule.value.protocol)
            source           = upper(stateful_rule.value.source)
            source_port      = upper(stateful_rule.value.source_port)
            destination      = upper(stateful_rule.value.destination)
            destination_port = upper(stateful_rule.value.destination_port)
            direction        = upper(stateful_rule.value.direction)
          }
          rule_option {
            keyword  = "sid"
            settings = [tostring(stateful_rule.value.sid)]
          }
        }
      }
    }
  }

  tags = merge({
    Name            = "${var.application}-${var.env}-five-tuple-rg-${var.region}"
    "Resource Type" = "five tuple rg"
    "Creation Date" = timestamp()
    "Environment"   = var.environment
    "Application"   = var.application
    "Created by"    = "Cloud Network Team"
    "Region"        = var.region
  }, var.base_tags)
}

// -------------------------------------------------------------------------
// Stateful Rule Group: Domain ALLOWLIST
// -------------------------------------------------------------------------
resource "aws_networkfirewall_rule_group" "domain_allowlist" {
  count = var.enable_domain_allowlist ? 1 : 0
  
  name        = "domain-allowlist-${var.firewall_policy_name}"
  description = "Domain allowlist rule group (AWS-managed FQDN filtering)."
  type        = "STATEFUL"
  capacity    = var.domain_rg_capacity

  rule_group {
    stateful_rule_options {
      rule_order = var.stateful_rule_order
    }

    rules_source {
      rules_source_list {
        targets              = var.domain_list
        target_types         = ["TLS_SNI", "HTTP_HOST"]
        generated_rules_type = "ALLOWLIST"
      }
    }
  }

  tags = merge({
    Name            = "${var.application}-${var.env}-domain-allow-rg-${var.region}"
    "Resource Type" = "domain-allow-rg"
    "Creation Date" = timestamp()
    "Environment"   = var.environment
    "Application"   = var.application
    "Created by"    = "Cloud Network Team"
    "Region"        = var.region
  }, var.base_tags)
}

// -------------------------------------------------------------------------
// Network Firewall Policy 
// -------------------------------------------------------------------------
resource "aws_networkfirewall_firewall_policy" "firewall_policy" {
  name = var.firewall_policy_name

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:drop"]

    stateful_default_actions = [
    "aws:drop_established",
    "aws:alert_established"
  ]

    # Reference Domain Allowlist
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_order == "STRICT_ORDER" && length(local.allowlist_arn_list) > 0 ? local.allowlist_arn_list : []
      content {
        resource_arn = stateful_rule_group_reference.value
        priority     = var.priority_domain_allowlist
      }
    }
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_order != "STRICT_ORDER" && length(local.allowlist_arn_list) > 0 ? local.allowlist_arn_list : []
      content {
        resource_arn = stateful_rule_group_reference.value
      }
    }

    # Reference 5-Tuple Group
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_order == "STRICT_ORDER" ? [aws_networkfirewall_rule_group.five_tuple_rule_group.arn] : []
      content {
        resource_arn = stateful_rule_group_reference.value
        priority     = var.priority_five_tuple
      }
    }
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_order != "STRICT_ORDER" ? [aws_networkfirewall_rule_group.five_tuple_rule_group.arn] : []
      content {
        resource_arn = stateful_rule_group_reference.value
      }
    }

    stateful_engine_options {
      rule_order = var.stateful_rule_order
    }

    # External Rule Groups
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_order != "STRICT_ORDER" ? var.stateful_rule_group_arns : []
      content { resource_arn = stateful_rule_group_reference.value }
    }
    dynamic "stateful_rule_group_reference" {
      for_each = var.stateful_rule_order == "STRICT_ORDER" ? var.stateful_rule_group_objects : []
      content {
        resource_arn = stateful_rule_group_reference.value.arn
        priority     = stateful_rule_group_reference.value.priority
      }
    }
  }

  tags = merge({
    Name            = "${var.application}-${var.env}-firewall-policy-${var.region}"
    "Resource Type" = "firewall-policy"
    "Creation Date" = timestamp()
    "Environment"   = var.environment
    "Application"   = var.application
    "Created by"    = "Cloud Network Team"
    "Region"        = var.region
  }, var.base_tags)
}