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
    Name            = "${var.application}-${var.environment}-five-tuple-rg-${var.region}"
    "Resource Type" = "five tuple rg"
    "Creation Date" = timestamp()
    "Environment"   = var.environment
    "Application"   = var.application
    "Created by"    = "Cloud Network Team"
    "Region"        = var.region
  }, var.base_tags)
}