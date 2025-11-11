# 1. ECR Repository
resource "aws_ecr_repository" "scanner_repository" {
  name                 = "cscat-scanner-repository-261111"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

# 2. Report S3 Bucket
resource "aws_s3_bucket" "report_bucket" {
  bucket = "cscat-security-reports-261111"

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

# Versioning (v5)
resource "aws_s3_bucket_versioning" "report_bucket_versioning" {
  bucket = aws_s3_bucket.report_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Public access block
resource "aws_s3_bucket_public_access_block" "report_bucket_public_access" {
  bucket = aws_s3_bucket.report_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# S3 website configuration
resource "aws_s3_bucket_website_configuration" "report_website" {
  bucket = aws_s3_bucket.report_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# Bucket policy
resource "aws_s3_bucket_policy" "website_read_policy" {
  bucket = aws_s3_bucket.report_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "PublicReadGetObject",
        Effect    = "Allow",
        Principal = "*",
        Action    = "s3:GetObject",
        Resource  = "${aws_s3_bucket.report_bucket.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.report_bucket_public_access]
}

# Outputs
output "ecr_repository_uri" {
  description = "The URI of the ECR repository"
  value       = aws_ecr_repository.scanner_repository.repository_url
}

output "report_bucket_name" {
  description = "The name of the S3 bucket for storing reports"
  value       = aws_s3_bucket.report_bucket.bucket
}

output "website_endpoint" {
  description = "The S3 static website endpoint for the front-end application"
  value       = aws_s3_bucket.report_bucket.website_endpoint
}
