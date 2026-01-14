resource "aws_networkfirewall_rule_group" "domain_allowlist" {
  count = var.enable_domain_allowlist ? 1 : 0
  
  name         = "domain-allowlist-${var.firewall_policy_name}"
  description  = "Domain allowlist rule group (AWS-managed FQDN filtering)."
  type         = "STATEFUL"
  capacity     = var.domain_rg_capacity

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