resource "aws_s3_bucket" "this" {
  bucket = "${var.application}-${var.env}-tmo-firewall-logs-bucket-1"
  force_destroy = true
  
    tags = merge(
  {
    Name                  = "${var.application}-${var.env}-fw-logs-bucket-1"
    "Resource Type"       = "s3-bucket"
    "Creation Date"       = timestamp()
    "Environment"         = var.environment
    "Application" = var.application
    "Created by"          = "Cloud Network Team"
    "breadthOfConsumption"  = "Single"
    "dataSensitivity"      = "Internal"
    "dangerOfExploitation"  = "INA"
  },var.base_tags
)
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "bucket_policy" {
  
  # Allow Firewall Log Delivery
  statement {
    sid    = "AllowNetworkFirewallLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = ["s3:PutObject", "s3:GetBucketAcl"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "RestrictAccessToTrustedIPs"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    
    condition {
      test     = "NotIpAddress"
      variable = "aws:SourceIp"
      values   = ["208.54.0.0/17", "206.29.160.0/19", "122.161.66.231/32"]
    }
    condition {
      test     = "Bool"
      variable = "aws:ViaAWSService"
      values   = ["false"]
    }
    
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*",
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
        ]
    }
  
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalServiceName"
      values   = ["delivery.logs.amazonaws.com"]
    }
  }

  # Deny non-TLS access
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    condition {
      test     = "Bool" 
      variable = "aws:SecureTransport" 
      values = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket     = aws_s3_bucket.this.id
  policy     = data.aws_iam_policy_document.bucket_policy.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# --- 3. LIFECYCLE RULE (180 Days) ---
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "lifecycle rule"
    status = "Enabled"
    filter {}

    expiration {
      days = 180
    }

    noncurrent_version_expiration {
      noncurrent_days = 180
    }
  }
}


