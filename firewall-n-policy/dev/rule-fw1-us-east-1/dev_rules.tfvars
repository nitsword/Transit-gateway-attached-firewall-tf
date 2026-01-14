region = "us-east-1"
transit_gateway_id    = "tgw-09396a29da000e3c8"
availability_zone_ids = ["use1-az1", "use1-az2", "use1-az4"]

application = "ntw"
env         = "dev"
#rules_directory = "policy_config/dev/rules-fw1-us-east1"
environment          = "Non-production::Dev"

# --- Directory Targeting ---
# This points to: fw-policy_config/dev/rules-fw1-us-east1/
# locals use this to find the /domain_list_rules/ and /five_tuple_rules/ folders
rule_set_name = "rule-fw1-us-east-1"

# --- Firewall Policy Configuration ---
firewall_name        = "inspection-firewall-dev"
firewall_policy_name = "inspection-firewall-policy-dev"
stateful_rule_order  = "STRICT_ORDER"

# --- Capacities & Priorities ---
priority_domain_allowlist = 10 
priority_five_tuple       = 20
priority_suricata         = 30

enable_domain_allowlist = true
domain_rg_capacity      = 100
five_tuple_rg_capacity  = 100
suricata_rg_capacity   = 200

# --- External Rule Groups ---
stateful_rule_group_arns    = []
stateful_rule_group_objects = []