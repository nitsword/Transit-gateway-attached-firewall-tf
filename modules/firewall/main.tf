locals {
  fw_name = "${var.application}-${var.env}-inspection-firewall-${var.region}"
}

# -------------------------------------------------------------------------
# 4. Network Firewall Resource
# -------------------------------------------------------------------------
resource "aws_networkfirewall_firewall" "inspection_firewall" {
  name                = local.fw_name
  firewall_policy_arn = var.firewall_policy_arn
  transit_gateway_id = var.transit_gateway_id

dynamic "availability_zone_mapping" {
    for_each = var.availability_zone_ids
    content {
      availability_zone_id = availability_zone_mapping.value
    }
  }

  delete_protection                = false
  firewall_policy_change_protection = false
    
  description       = "Transit gateway attached Firewall"

  tags = merge(
  {
    Name                  = "${var.application}-${var.env}-firewall-${var.region}"
    "Resource Type"       = "firewall"
    "Creation Date"       = timestamp()
    "Environment"         = var.environment
    "Application" = var.application
    "Created by"          = "Cloud Network Team"
    "Region"              = var.region
  },var.base_tags
)
}
