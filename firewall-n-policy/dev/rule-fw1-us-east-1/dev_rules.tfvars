region = "us-east-1"
transit_gateway_id    = "tgw-09396a29da000e3c8"
availability_zone_ids = ["use1-az1", "use1-az2", "use1-az4"]

application = "ntw"
env         = "dev"
#rules_directory = "policy_config/dev/rules-fw1-us-east1"
environment          = "Non-production::Dev"

firewall_policy_name = "inspection-firewall-policy-dev"
stateful_rule_order = "STRICT_ORDER"
 
priority_domain_allowlist = 10  # Second priority 
priority_five_tuple       = 20  # Lowest priority

enable_domain_allowlist = true

# --- 5-Tuple Rule Group Content ---

five_tuple_rg_capacity    = 100
five_tuple_rules_csv_path = "firewall-n-policy/dev/rule-fw1-us-east-1/five_tuple_rules.csv"

rules_csv_path = "firewall-n-policy/dev/rule-fw1-us-east-1/dev_rules.csv"

# --- Domain Rule Group (FQDN) Inputs ---

domain_rg_capacity = 100

stateful_rule_group_objects = [ ]
