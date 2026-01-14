resource "aws_networkfirewall_rule_group" "suricata_rule_group" {
  name     = "${var.application}-${var.env}-suricata-rg-${var.region}"
  capacity = var.suricata_rg_capacity
  type     = "STATEFUL"

  rule_group {
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = var.home_net_cidrs
        }
      }
    }

    rules_source {
      
      rules_string = var.rules_string
    }

    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }

  tags = merge({
    Name            = "${var.application}-${var.env}-suricata-rg-${var.region}"
    "Resource Type" = "suricata-rg"
    "Creation Date" = timestamp()
    "Environment"   = var.environment
    "Application"   = var.application
    "Created by"    = "Cloud Network Team"
    "Region"        = var.region
  }, var.base_tags)
}