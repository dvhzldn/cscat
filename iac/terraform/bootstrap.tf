provider "aws" {
  region = "eu-west-2"
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "tf_backend" {
  bucket = "cscat-terraform-state-261111"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# Separate resource for versioning (v5-compliant)
resource "aws_s3_bucket_versioning" "tf_backend_versioning" {
  bucket = aws_s3_bucket.tf_backend.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "tf_backend_policy" {
  bucket = aws_s3_bucket.tf_backend.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/GitHubActions-DevSecOps-Role"
        },
        Action   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:DeleteObject"
        ],
        Resource = [
          aws_s3_bucket.tf_backend.arn,
          "${aws_s3_bucket.tf_backend.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_dynamodb_table" "tf_lock_table" {
  name         = "cscat-terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
