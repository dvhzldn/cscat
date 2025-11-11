# Define the AWS provider configuration
provider "aws" {
  region = var.aws_region
}

# 1. Resource for the ECR Repository
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

# 2. Resource for the report and site S3 Bucket
resource "aws_s3_bucket" "report_bucket" {
  bucket = "cscat-security-reports-261111"

  website {
    index_document = "index.html"
    error_document = "error.html"
  }

  versioning {
    enabled = true
  }

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

resource "aws_s3_bucket_policy" "website_read_policy" {
  bucket = aws_s3_bucket.report_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.report_bucket.arn}/*"
      },
    ]
  })
}

# 3. Output the ECR Repository URI for the CI/CD pipeline
output "ecr_repository_uri" {
  description = "The URI of the ECR repository"
  value       = aws_ecr_repository.scanner_repository.repository_url
}

# 4. Output the S3 Bucket Name for the Lambda function
output "report_bucket_name" {
  description = "The name of the S3 bucket for storing reports"
  value       = aws_s3_bucket.report_bucket.bucket
}

# 5. Output URL endpoint for front-end access
output "website_endpoint" {
  description = "The S3 static website endpoint for the front-end application"
  value       = aws_s3_bucket.report_bucket.website_endpoint
}
