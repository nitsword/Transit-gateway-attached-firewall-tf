terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.5"
    }
  }
}


provider "aws" {
  region = var.region
}

locals {
  # Dynamic Path Construction
  rules_base_path = "firewall-n-policy/${var.env}/${var.rule_set_name}"

  # ---------------------------------------------------------------------------
  # DOMAIN LIST RULES: Merging multiple CSVs
  # ---------------------------------------------------------------------------
  domain_files = fileset(path.module, "${local.rules_base_path}/domain_list_rules/*.csv")

  # Decode all files and flatten into a single list of maps
  all_domain_data = flatten([
    for f in local.domain_files : csvdecode(file("${path.module}/${f}"))
  ])

  allowed_domains = distinct([
    for d in local.all_domain_data : trimspace(d.domain)
    if lookup(d, "action", "") != "" && upper(trimspace(d.action)) == "ALLOW"
  ])

  # ---------------------------------------------------------------------------
  # 5-TUPLE RULES: Merging multiple CSVs
  # ---------------------------------------------------------------------------
  tuple_files = fileset(path.module, "${local.rules_base_path}/five_tuple_rules/*.csv")

  all_tuple_data = flatten([
    for f in local.tuple_files : csvdecode(file("${path.module}/${f}"))
  ])

  five_tuple_rules = [
    for i, r in local.all_tuple_data : {
      action           = upper(lookup(r, "action", "PASS"))
      protocol         = upper(lookup(r, "protocol", "TCP"))
      source           = lookup(r, "source", "ANY") == "" ? "ANY" : upper(r.source)
      source_port      = lookup(r, "source_port", "ANY") == "" ? "ANY" : upper(r.source_port)
      destination      = lookup(r, "destination", "ANY") == "" ? "ANY" : upper(r.destination)
      destination_port = lookup(r, "destination_port", "ANY") == "" ? "ANY" : upper(r.destination_port)
      direction        = "FORWARD"
      # Generates unique SIDs starting from 1000001 based on index in merged list
      sid = tostring(lookup(r, "sid", 1000001 + i))
    }
  ]
}


# Module for Domain List Rules
module "domain_rules" {
  source                    = "./modules/domain_list_rules"
  environment               = var.environment
  application               = var.application
  region                    = var.region
  env                       = var.env
  base_tags                 = var.base_tags
  firewall_policy_name      = var.firewall_policy_name
  domain_list               = local.allowed_domains
  enable_domain_allowlist   = var.enable_domain_allowlist
  domain_rg_capacity        = var.domain_rg_capacity
  stateful_rule_order       = var.stateful_rule_order
  rule_set_name             = var.rule_set_name
  priority_domain_allowlist = var.priority_domain_allowlist
}

# Module for 5-Tuple Rules
module "five_tuple_rules" {
  source                 = "./modules/five_tuple_rules"
  environment            = var.environment
  application            = var.application
  region                 = var.region
  env                    = var.env
  base_tags              = var.base_tags
  firewall_policy_name   = var.firewall_policy_name
  five_tuple_rules       = local.five_tuple_rules
  five_tuple_rg_capacity = var.five_tuple_rg_capacity
  stateful_rule_order    = var.stateful_rule_order
  priority_five_tuple    = var.priority_five_tuple

}

# Firewall Policy Module
module "firewall_policy_conf" {
  source               = "./modules/firewall_policy_conf"
  environment          = var.environment
  application          = var.application
  region               = var.region
  env                  = var.env
  base_tags            = var.base_tags
  firewall_policy_name = var.firewall_policy_name
  stateful_rule_order  = var.stateful_rule_order

  domain_group_arn     = try(module.domain_rules.rule_group_arn, null)
  five_tuple_group_arn = module.five_tuple_rules.rule_group_arn

  stateful_rule_group_arns    = var.stateful_rule_group_arns
  stateful_rule_group_objects = var.stateful_rule_group_objects
  priority_domain_allowlist   = var.priority_domain_allowlist
  priority_five_tuple         = var.priority_five_tuple
}

module "firewall" {
  source                = "./modules/firewall"
  application           = var.application
  environment           = var.environment
  region                = var.region
  env                   = var.env
  base_tags             = var.base_tags
  firewall_name         = var.firewall_name
  firewall_policy_name  = var.firewall_policy_name
  firewall_policy_arn   = module.firewall_policy_conf.firewall_policy_arn
  transit_gateway_id    = var.transit_gateway_id
  availability_zone_ids = var.availability_zone_ids
  depends_on            = [module.secure_s3_bucket]
}

module "secure_s3_bucket" {
  source                 = "./modules/s3_bucket"
  application            = var.application
  environment            = var.environment
  env                    = var.env
  base_tags              = var.base_tags
  bucket_name            = var.bucket_name
  allowed_principal_arns = ["arn:aws:iam::359416636780:user/terraform-test"]
}

# Configure Logging
resource "aws_networkfirewall_logging_configuration" "this" {
  firewall_arn = module.firewall.firewall_arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        bucketName = module.secure_s3_bucket.bucket_id
        prefix     = "alerts"
      }
      log_destination_type = "S3"
      log_type             = "ALERT"
    }
    # 3. TLS Logs (Encryption Handshake Events)
    log_destination_config {
      log_destination = {
        bucketName = module.secure_s3_bucket.bucket_id
        prefix     = "tls"
      }
      log_destination_type = "S3"
      log_type             = "TLS"
    }
  }
}

