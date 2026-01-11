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
  domain_list_data = csvdecode(file(var.rules_csv_path))
  allowed_domains = [
    for d in local.domain_list_data : trimspace(d.domain)
    if lookup(d, "action", "") != "" && upper(trimspace(d.action)) == "ALLOW"
  ]

  five_tuple_rules_data = csvdecode(file(var.five_tuple_rules_csv_path))

  five_tuple_rules = [
    for i, r in local.five_tuple_rules_data : {
      action           = upper(lookup(r, "action", "PASS"))
      protocol         = upper(lookup(r, "protocol", "TCP"))
      source           = upper(lookup(r, "source", "ANY"))
      source_port      = upper(lookup(r, "source_port", "ANY"))
      destination      = upper(lookup(r, "destination", "ANY"))
      destination_port = upper(lookup(r, "destination_port", "ANY"))
      direction        = "FORWARD"
      sid              = tostring(lookup(r, "sid", 1000001 + i))
    }
  ]
}


module "firewall_policy_conf" {
  source                      = "./modules/firewall_policy_conf"
  environment                 = var.environment
  application                 = var.application
  region                      = var.region
  env                         = var.env
  base_tags                   = var.base_tags
  firewall_policy_name        = var.firewall_policy_name
  five_tuple_rg_capacity      = var.five_tuple_rg_capacity
  five_tuple_rules            = local.five_tuple_rules
  domain_list                 = local.allowed_domains
  enable_domain_allowlist     = var.enable_domain_allowlist
  domain_rg_capacity          = var.domain_rg_capacity
  stateful_rule_group_arns    = var.stateful_rule_group_arns
  stateful_rule_order         = var.stateful_rule_order
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

