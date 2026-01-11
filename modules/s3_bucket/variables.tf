variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
}

variable "tags" {
  description = "Tags to apply to the bucket"
  type        = map(string)
  default     = {}
}

variable "allowed_principal_arns" {
  description = "List of IAM principal ARNs allowed full access"
  type        = list(string)
  default = []
}

variable "application" { type = string }
variable "environment" { type = string }
variable "base_tags" { type = map(string) }
variable "env" { type = string }